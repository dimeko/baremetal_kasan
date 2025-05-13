#include "heap.h"
#include "kasan_dlmalloc.h"
#include "kasan_common.h"

static void poison_mem(void *address, size_t size, size_t aligned_size) {
  unpoison_shadow((unsigned long)(address + KASAN_HEAP_HEAD_REDZONE_SIZE), size);
  poison_shadow((unsigned long)address, KASAN_HEAP_HEAD_REDZONE_SIZE,
      ASAN_SHADOW_HEAP_HEAD_REDZONE_MAGIC);
  poison_shadow(
      (unsigned long)(address + KASAN_HEAP_HEAD_REDZONE_SIZE + aligned_size),
      KASAN_HEAP_TAIL_REDZONE_SIZE, ASAN_SHADOW_HEAP_TAIL_REDZONE_MAGIC);
}

void *sbrk(ptrdiff_t increment)
{
	unsigned long old = mem_malloc_brk;
	unsigned long new = old + increment;

	if ((new < mem_malloc_start) || (new > mem_malloc_end))
		return (void *)MORECORE_FAILURE;

	/*
	 * if we are giving memory back make sure we clear it out since
	 * we set MORECORE_CLEARS to 1
	 */
	if (increment < 0)
		memset((void *)new, 0, -increment);

	mem_malloc_brk = new;

	return (void *)old;
}

// ------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------dlmalloc_trim--------------------------------------
// ------------------------------------------------------------------------------------------------------------

int dlmalloc_trim(size_t pad) {
  long  top_size;        /* Amount of top-most memory */
  long  extra;           /* Amount to release */
  char* current_brk;     /* address returned by pre-check sbrk call */
  char* new_brk;         /* address returned by negative sbrk call */

  unsigned long pagesz = malloc_getpagesize;

  top_size = chunksize(top);
  extra = ((top_size - pad - MINSIZE + (pagesz-1)) / pagesz - 1) * pagesz;

  if (extra < (long)pagesz)  /* Not enough memory to release */
    return 0;

  else {
    /* Test to make sure no one else called sbrk */
    current_brk = (char*)(MORECORE (0));
    if (current_brk != (char*)(top) + top_size)
      return 0;     /* Apparently we don't own memory; must fail */
    else {
      new_brk = (char*)(MORECORE (-extra));

      if (new_brk == (char*)(MORECORE_FAILURE)) /* sbrk failed? */
      {
        /* Try to figure out what we have */
        current_brk = (char*)(MORECORE (0));
        top_size = current_brk - (char*)top;
        if (top_size >= (long)MINSIZE) /* if not, we are very very dead! */
        {
          sbrked_mem = current_brk - sbrk_base;
          set_head(top, top_size | PREV_INUSE);
        }
        return 0;
      } else
      {
        /* Success. Adjust top accordingly. */
        set_head(top, (top_size - extra) | PREV_INUSE);
        sbrked_mem -= extra;
        return 1;
      }
    }
  }
}


// ------------------------------------------------------------------------------------------------------------
// ------------------------------------------------kasan_dlfree_hook-------------------------------------------
// ------------------------------------------------------------------------------------------------------------

void kasan_dlfree_hook(void* mem) {
  mchunkptr p;         /* chunk corresponding to mem */
  INTERNAL_SIZE_T hd;  /* its head field */
  INTERNAL_SIZE_T sz;  /* its size */
  int       idx;       /* its bin index */
  mchunkptr next;      /* next contiguous chunk */
  INTERNAL_SIZE_T nextsz; /* its size */
  INTERNAL_SIZE_T prevsz; /* size of previous contiguous chunk */
  mchunkptr bck;       /* misc temp for linking */
  mchunkptr fwd;       /* misc temp for linking */
  int       islr;      /* track whether merging with last_remainder */

  if (mem == NULL)                              /* free(0) has no effect */
    return;

  p = mem2chunkBeforeRedzone(mem);
  hd = p->size;

  sz = hd & ~PREV_INUSE;
  next = chunk_at_offset(p, sz);
  nextsz = chunksize(next);
  if (next == top)                            /* merge with top */
  {
    sz += nextsz;

    if (!(hd & PREV_INUSE))                    /* consolidate backward */
    {
      prevsz = p->prev_size;
      p = chunk_at_offset(p, -((long) prevsz));
      sz += prevsz;
      unlink(p, bck, fwd);
    }

    set_head(p, sz | PREV_INUSE);
    top = p;
    if ((unsigned long)(sz) >= (unsigned long)trim_threshold)
      dlmalloc_trim(top_pad);

    poison_shadow((unsigned long)chunk2mem(p), chunkUserSize(p), ASAN_SHADOW_HEAP_FREE_MAGIC);
    return;
  }

  set_head(next, nextsz);                    /* clear inuse bit */

  islr = 0;

  if (!(hd & PREV_INUSE))                    /* consolidate backward */
  {
    prevsz = p->prev_size;
    p = chunk_at_offset(p, -((long) prevsz));
    sz += prevsz;

    if (p->fd == last_remainder)             /* keep as last_remainder */
      islr = 1;
    else
      unlink(p, bck, fwd);
  }

  if (!(inuse_bit_at_offset(next, nextsz))) {
    sz += nextsz;

    if (!islr && next->fd == last_remainder)  /* re-insert last_remainder */
    {
      islr = 1;
      link_last_remainder(p);
    }
    else
      unlink(next, bck, fwd);
  }

  set_head(p, sz | PREV_INUSE);
  set_foot(p, sz);
  if (!islr)
    frontlink(p, sz, idx, bck, fwd);
  poison_shadow((unsigned long)chunk2mem(p), chunkUserSize(p), ASAN_SHADOW_HEAP_FREE_MAGIC);

}
// ------------------------------------------------------------------------------------------------------------
// ----------------------------------------------malloc_extend_top---------------------------------------------
// ------------------------------------------------------------------------------------------------------------

static void malloc_extend_top(INTERNAL_SIZE_T nb) {
  char*     brk;                  /* return value from sbrk */
  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of sbrked space */
  INTERNAL_SIZE_T correction;     /* bytes for 2nd sbrk call */
  char*     new_brk;              /* return of 2nd sbrk call */
  INTERNAL_SIZE_T top_size;       /* new size of top chunk */

  mchunkptr old_top     = top;  /* Record state of old top */
  INTERNAL_SIZE_T old_top_size = chunksize(old_top);
  char*     old_end      = (char*)(chunk_at_offset(old_top, old_top_size));

  /* Pad request with top_pad plus minimal overhead */

  INTERNAL_SIZE_T    sbrk_size     = nb + top_pad + MINSIZE;
  unsigned long pagesz    = malloc_getpagesize;

  /* If not the first time through, round to preserve page boundary */
  /* Otherwise, we need to correct to a page size below anyway. */
  /* (We also correct below if an intervening foreign sbrk call.) */

  if (sbrk_base != (char*)(-1))
    sbrk_size = (sbrk_size + (pagesz - 1)) & ~(pagesz - 1);

  brk = (char*)(MORECORE (sbrk_size));

  /* Fail if sbrk failed or if a foreign sbrk call killed our space */
  if (brk == (char*)(MORECORE_FAILURE) || (brk < old_end && old_top != initial_top)) return;

  sbrked_mem += sbrk_size;

  if (brk == old_end) {
    top_size = sbrk_size + old_top_size;
    set_head(top, top_size | PREV_INUSE);
  }
  else {
    if (sbrk_base == (char*)(-1))  sbrk_base = brk;
    else sbrked_mem += brk - (char*)old_end;

    front_misalign = (unsigned long)chunk2mem(brk) & MALLOC_ALIGN_MASK;
    if (front_misalign > 0) {
      correction = (MALLOC_ALIGNMENT) - front_misalign;
      brk += correction;
    }
    else correction = 0;
    correction += ((((unsigned long)(brk + sbrk_size))+(pagesz-1)) &
		   ~(pagesz - 1)) - ((unsigned long)(brk + sbrk_size));

    /* Allocate correction */
    new_brk = (char*)(MORECORE (correction));
    if (new_brk == (char*)(MORECORE_FAILURE)) return;

    sbrked_mem += correction;

    top = (mchunkptr)brk;
    top_size = new_brk - brk + correction;
    set_head(top, top_size | PREV_INUSE);

    if (old_top != initial_top)
    {

      /* There must have been an intervening foreign sbrk call. */
      /* A double fencepost is necessary to prevent consolidation */

      /* If not enough space to do this, then user did something very wrong */
      if (old_top_size < MINSIZE)
      {
        set_head(top, PREV_INUSE); /* will force null return from malloc */
        return;
      }

      /* Also keep size a multiple of MALLOC_ALIGNMENT */
      old_top_size = (old_top_size - 3*SIZE_SZ) & ~MALLOC_ALIGN_MASK;
      set_head_size(old_top, old_top_size);
      chunk_at_offset(old_top, old_top_size)->size = SIZE_SZ|PREV_INUSE;
      chunk_at_offset(old_top, old_top_size + SIZE_SZ)->size =SIZE_SZ|PREV_INUSE;
      /* If possible, release the rest. */
      if (old_top_size >= MINSIZE) kasan_dlfree_hook(chunk2memAfterRedzone(old_top));
    }
  }

  if ((unsigned long)sbrked_mem > (unsigned long)max_sbrked_mem)
    max_sbrked_mem = sbrked_mem;
  if ((unsigned long)(mmapped_mem + sbrked_mem) > (unsigned long)max_total_mem)
    max_total_mem = mmapped_mem + sbrked_mem;

  /* We always land on a page boundary */
}

// ------------------------------------------------------------------------------------------------------------
// -------------------------------------------------------dlmalloc---------------------------------------------
// ------------------------------------------------------------------------------------------------------------

void *kasan_dlmalloc_hook(size_t bytes) {
  mchunkptr victim;                  /* inspected/selected chunk */
  INTERNAL_SIZE_T victim_size;       /* its size */
  int       idx;                     /* index for bin traversal */
  mbinptr   bin;                     /* associated bin */
  mchunkptr remainder;               /* remainder from a split */
  long      remainder_size;          /* its size */
  int       remainder_index;         /* its bin index */
  unsigned long block;               /* block traverser bit */
  int       startidx;                /* first bin of a traversed block */
  mchunkptr fwd;                     /* misc temp for linking */
  mchunkptr bck;                     /* misc temp for linking */
  mbinptr q;                         /* misc temp */

  INTERNAL_SIZE_T nb;
  /* check if initialize_dlmalloc_heap() was run */

  if ((mem_malloc_start == 0) && (mem_malloc_end == 0)) {
    return NULL;
  }

  if (bytes > HEAP_SIZE || (long)bytes < 0) return NULL;

  nb = request2size(bytes);  /* padded request size; */
  unsigned int total_kasan_size = nb + \
    KASAN_HEAP_HEAD_REDZONE_SIZE + \
    KASAN_HEAP_TAIL_REDZONE_SIZE;

  if (is_small_request(total_kasan_size))  /* Faster version for small requests */ {
    idx = smallbin_index(total_kasan_size);
    /* No traversal or size check necessary for small bins.  */

    q = bin_at(idx);
    victim = last(q);

    if (victim == q) {
      q = next_bin(q);
      victim = last(q);
    }
    if (victim != q) {
      victim_size = chunksize(victim); // here we have to find the KASAN chunk size adding REDZONES back and forth
      unlink(victim, bck, fwd); // KASAN does not need to do anything
      set_inuse_bit_at_offset(victim, victim_size); // ??? probably not anything to do here

      poison_mem(chunk2mem(victim), bytes, nb);
      return chunk2memAfterRedzone(victim);
    }

    idx += 2;
  }
  else {
    idx = bin_index(total_kasan_size);
    bin = bin_at(idx);

    for (victim = last(bin); victim != bin; victim = victim->bk)
    {
      victim_size = chunksize(victim);

      remainder_size = victim_size - total_kasan_size;

      if (remainder_size >= (long)MINSIZE) {
	      --idx;
	      break;
      } else if (remainder_size >= 0) {

        unlink(victim, bck, fwd);
        set_inuse_bit_at_offset(victim, victim_size);
        poison_mem(chunk2mem(victim), bytes, nb);
        return chunk2memAfterRedzone(victim);
      }
    }
    ++idx;
  }

  if ( (victim = last_remainder->fd) != last_remainder)
  {
    victim_size = chunksize(victim);

    remainder_size = victim_size - total_kasan_size;

    if (remainder_size >= (long)MINSIZE){
      remainder = chunk_at_offset(victim, total_kasan_size);
      set_head(victim, total_kasan_size | PREV_INUSE);
      link_last_remainder(remainder);
      set_head(remainder, remainder_size | PREV_INUSE);
      set_foot(remainder, remainder_size);

      poison_mem(chunk2mem(victim), bytes, nb);
      return chunk2memAfterRedzone(victim);
    }

    clear_last_remainder;

    if (remainder_size >= 0) {
      set_inuse_bit_at_offset(victim, victim_size);

      poison_mem(chunk2mem(victim), bytes, nb);
      return chunk2memAfterRedzone(victim);
    }

    frontlink(victim, victim_size, remainder_index, bck, fwd);
  }


  if ( (block = idx2binblock(idx)) <= binblocks_r) {

    if ( (block & binblocks_r) == 0){
      idx = (idx & ~(BINBLOCKWIDTH - 1)) + BINBLOCKWIDTH;
      block <<= 1;
      while ((block & binblocks_r) == 0)
      {
        idx += BINBLOCKWIDTH;
        block <<= 1;
      }
    }

    for (;;) {
      startidx = idx;
      q = bin = bin_at(idx);

      /* For each bin in this block ... */
      do {
        for (victim = last(bin); victim != bin; victim = victim->bk) {
          victim_size = chunksize(victim);

          remainder_size = victim_size - total_kasan_size;

          if (remainder_size >= (long)MINSIZE) {
            remainder = chunk_at_offset(victim, total_kasan_size);
            set_head(victim, total_kasan_size | PREV_INUSE);
            unlink(victim, bck, fwd);
            link_last_remainder(remainder);
            set_head(remainder, remainder_size | PREV_INUSE);
            set_foot(remainder, remainder_size);

            poison_mem(chunk2mem(victim), bytes, nb);
            return chunk2memAfterRedzone(victim);
          } else if (remainder_size >= 0)  {
            set_inuse_bit_at_offset(victim, victim_size);
            unlink(victim, bck, fwd);

            poison_mem(chunk2mem(victim), bytes, nb);
            return chunk2memAfterRedzone(victim);
          }
	      }

        bin = next_bin(bin);

      } while ((++idx & (BINBLOCKWIDTH - 1)) != 0);

      do  {
        if ((startidx & (BINBLOCKWIDTH - 1)) == 0) {
          av_[1] = (mbinptr)(binblocks_r & ~block);
          break;
        }
	      --startidx;
        q = prev_bin(q);
      } while (first(q) == q);
      if ( (block <<= 1) <= binblocks_r && (block != 0) ) {
        while ((block & binblocks_r) == 0) {
          idx += BINBLOCKWIDTH;
          block <<= 1;
        }
      }
      else break;
    }
  }

  /* Require that there be a remainder, ensuring top always exists  */
  if ( (remainder_size = chunksize(top) - total_kasan_size) < (long)MINSIZE) {

    malloc_extend_top(total_kasan_size);
    if ( (remainder_size = chunksize(top) - total_kasan_size) < (long)MINSIZE)
      return NULL; /* propagate failure */
  }
  victim = top;
  set_head(victim, total_kasan_size | PREV_INUSE);
  top = chunk_at_offset(victim, total_kasan_size);
  set_head(top, remainder_size | PREV_INUSE);
  poison_mem(chunk2mem(victim), bytes, nb);

  return chunk2memAfterRedzone(victim);
}

