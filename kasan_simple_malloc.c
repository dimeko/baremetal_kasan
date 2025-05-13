#include "heap.h"
#include "common.h"
#include "kasan_common.h"
#include "kasan_simple_malloc.h"

void *allocate_chunk(unsigned long size) {
  void *result = (void *)mem_malloc_start;
  if (size > mem_malloc_size) return NULL;

  size = (size + 7) & (~7UL);
  mem_malloc_start += size;
  mem_malloc_size -= size;
  return result;
}

void *kasan_malloc_hook(unsigned int size) {
  struct KASAN_HEAP_HEADER *kasan_heap_hdr = NULL;
  unsigned int algined_size = (size + KASAN_SHADOW_MASK) & (~KASAN_SHADOW_MASK);
  unsigned int total_size = algined_size + KASAN_HEAP_HEAD_REDZONE_SIZE +
                            KASAN_HEAP_TAIL_REDZONE_SIZE;

  void *ptr = allocate_chunk(total_size);
  if (ptr == NULL) return NULL;

  kasan_heap_hdr = (struct KASAN_HEAP_HEADER *)ptr;
  kasan_heap_hdr->aligned_size = algined_size;

  unpoison_shadow((unsigned long)(ptr + KASAN_HEAP_HEAD_REDZONE_SIZE), size);
  poison_shadow((unsigned long)ptr, KASAN_HEAP_HEAD_REDZONE_SIZE,
                ASAN_SHADOW_HEAP_HEAD_REDZONE_MAGIC);
  poison_shadow(
      (unsigned long)(ptr + KASAN_HEAP_HEAD_REDZONE_SIZE + algined_size),
      KASAN_HEAP_TAIL_REDZONE_SIZE, ASAN_SHADOW_HEAP_TAIL_REDZONE_MAGIC);

  return ptr + KASAN_HEAP_HEAD_REDZONE_SIZE;
}
  
void kasan_free_hook(void *ptr) {
  struct KASAN_HEAP_HEADER *kasan_heap_hdr = NULL;
  unsigned int aligned_size = 0;

  if (ptr == NULL) return;

  kasan_heap_hdr =
      (struct KASAN_HEAP_HEADER *)(ptr - KASAN_HEAP_HEAD_REDZONE_SIZE);
  aligned_size = kasan_heap_hdr->aligned_size;

  free_chunk(kasan_heap_hdr);
  poison_shadow((unsigned long)ptr, aligned_size, ASAN_SHADOW_HEAP_FREE_MAGIC);

  return;
}