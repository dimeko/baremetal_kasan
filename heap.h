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
#include "common.h"

#ifndef __KASAN_HEAP_H__
#define __KASAN_HEAP_H__

extern size_t mem_malloc_size;
extern unsigned long mem_malloc_start;
extern unsigned long mem_malloc_end;
extern unsigned long mem_malloc_brk;

void initialize_heap(void);
void free_chunk(void *ptr);
void *malloc(unsigned long size);
void free(void *ptr);

#endif  // __KASAN_HEAP_H__