
#ifndef __KASAN_SIMPLE_MALLOC__
#define __KASAN_SIMPLE_MALLOC__

struct KASAN_HEAP_HEADER {
  unsigned int aligned_size;
};

void *kasan_malloc_hook(unsigned int size);
void kasan_free_hook(void *ptr);

#endif // __KASAN_SIMPLE_MALLOC__