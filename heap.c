/*
 * Copyright 2024 Google LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#pragma

#include "common.h"
#include "kasan_common.h"
#include "kasan_simple_malloc.h"
#include "kasan_dlmalloc.h"
#include "heap.h"
#include "printf.h"

// These symbols are defined in the linker script.
extern char __heap_start;
extern char __heap_end;

size_t mem_malloc_size = 0;
unsigned long mem_malloc_start = 0;
unsigned long mem_malloc_end = 0;
unsigned long mem_malloc_brk = 0;

void initialize_heap(void) {
  mem_malloc_start = (unsigned long)&__heap_start;
  mem_malloc_end = (unsigned long)&__heap_end;
  mem_malloc_size = mem_malloc_end - mem_malloc_start;
  mem_malloc_brk = mem_malloc_start;
  initialize_kasan();
}

void free_chunk(void *ptr) { (void)ptr; }

void *malloc(unsigned long size) { 
  #ifdef DLMALLOC_ENABLED
  return kasan_dlmalloc_hook(size); 
  #else
  return kasan_malloc_hook(size); 
  #endif // DLMALLOC_ENABLED
}

void free(void *ptr) {
  #ifdef DLMALLOC_ENABLED
  return kasan_dlfree_hook(ptr); 
  #else
  return kasan_free_hook(ptr); 
  #endif // DLMALLOC_ENABLED
}