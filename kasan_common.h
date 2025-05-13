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
#ifndef __KASAN_COMMON__
#define __KASAN_COMMON__

#define KASAN_SHADOW_SHIFT 3
#define KASAN_SHADOW_GRANULE_SIZE (1UL << KASAN_SHADOW_SHIFT)
#define KASAN_SHADOW_MASK (KASAN_SHADOW_GRANULE_SIZE - 1)

#define ASAN_SHADOW_UNPOISONED_MAGIC 0x00
#define ASAN_SHADOW_RESERVED_MAGIC 0xff
#define ASAN_SHADOW_GLOBAL_REDZONE_MAGIC 0xf9
#define ASAN_SHADOW_HEAP_HEAD_REDZONE_MAGIC 0xfa
#define ASAN_SHADOW_HEAP_TAIL_REDZONE_MAGIC 0xfb
#define ASAN_SHADOW_HEAP_FREE_MAGIC 0xfd

#define KASAN_HEAP_HEAD_REDZONE_SIZE 0x20
#define KASAN_HEAP_TAIL_REDZONE_SIZE 0x20

#define KASAN_MEM_TO_SHADOW(addr) \
    (((addr) >> KASAN_SHADOW_SHIFT) + KASAN_SHADOW_MAPPING_OFFSET)
#define KASAN_SHADOW_TO_MEM(shadow) \
    (((shadow) - KASAN_SHADOW_MAPPING_OFFSET) << KASAN_SHADOW_SHIFT)

void initialize_kasan(void);
void poison_shadow(unsigned long address, size_t size, uint8_t value);
void unpoison_shadow(unsigned long address, size_t size);

#endif