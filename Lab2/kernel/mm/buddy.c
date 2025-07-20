/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS),
 * Shanghai Jiao Tong University (SJTU) Licensed under the Mulan PSL v2. You can
 * use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE. See the
 * Mulan PSL v2 for more details.
 */

#include <common/util.h>
#include <common/macro.h>
#include <common/kprint.h>
#include <mm/buddy.h>

__maybe_unused static struct page *get_buddy_chunk(struct phys_mem_pool *pool,
                                                   struct page *chunk)
{
        vaddr_t chunk_addr;
        vaddr_t buddy_chunk_addr;
        int order;

        /* Get the address of the chunk. */
        chunk_addr = (vaddr_t)page_to_virt(chunk);
        order = chunk->order;
        /*
         * Calculate the address of the buddy chunk according to the address
         * relationship between buddies.
         */
        buddy_chunk_addr = chunk_addr
                           ^ (1UL << (order + BUDDY_PAGE_SIZE_ORDER));

        /* Check whether the buddy_chunk_addr belongs to pool. */
        if ((buddy_chunk_addr < pool->pool_start_addr)
            || ((buddy_chunk_addr + (1 << order) * BUDDY_PAGE_SIZE)
                > (pool->pool_start_addr + pool->pool_mem_size))) {
                return NULL;
        }

        return virt_to_page((void *)buddy_chunk_addr);
}

/* The most recursion level of split_chunk is decided by the macro of
 * BUDDY_MAX_ORDER. */
__maybe_unused static struct page *split_chunk(struct phys_mem_pool *__maybe_unused pool,
                                int __maybe_unused order,
                                struct page *__maybe_unused chunk)
{
        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Recursively put the buddy of current chunk into
         * a suitable free list.
         */
        int current_order;
        struct page *buddy;

        /* Get the current order of the chunk */
        current_order = chunk->order;

        /* If we've reached the desired order, return the chunk */
        if (current_order == order) {
                chunk->allocated = 1;
                return chunk;
        }

        /* Split the chunk into two buddies */
        current_order--;
        buddy = chunk + (1 << current_order);

        /* Initialize buddy's metadata */
        buddy->allocated = 0;
        buddy->order = current_order;
        buddy->pool = pool;

        /* Update the original chunk's metadata */
        chunk->order = current_order;

        /* Add the buddy to the appropriate free list */
        list_add(&buddy->node, &pool->free_lists[current_order].free_list);
        pool->free_lists[current_order].nr_free++;

        /* Recursively split the remaining chunk */
        return split_chunk(pool, order, chunk);
        /* LAB 2 TODO 1 END */
}

/* The most recursion level of merge_chunk is decided by the macro of
 * BUDDY_MAX_ORDER. */
__maybe_unused static struct page * merge_chunk(struct phys_mem_pool *__maybe_unused pool,
                                struct page *__maybe_unused chunk)
{
        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Recursively merge current chunk with its buddy
         * if possible.
         */
        unsigned long chunk_idx, buddy_idx;
        struct page *buddy;
        int order = chunk->order;

        // 当块的order达到BUDDY_MAX_ORDER-1时停止合并（已经达到最大块大小）
        if (order >= BUDDY_MAX_ORDER - 1)
                return chunk;

        /* Calculate buddy's index */
        chunk_idx = chunk - pool->page_metadata;
        buddy_idx = chunk_idx ^ (1 << order);
        buddy = pool->page_metadata + buddy_idx;

        /* Check if buddy is free and of the same order */
        if (buddy->allocated == 0 && buddy->order == order) {
                /* Remove both chunks from their free lists */
                list_del(&chunk->node);
                list_del(&buddy->node);
                pool->free_lists[order].nr_free -= 2;

                /* Determine which page will be the merged block */
                if (chunk_idx > buddy_idx) {
                        chunk = buddy;
                }

                /* Increase the order of the merged block */
                chunk->order++;

                /* Recursively try to merge further */
                return merge_chunk(pool, chunk);
        }

        /* If no merge possible, return the original chunk */
        return chunk;
        /* LAB 2 TODO 1 END */
}

/*
 * The layout of a phys_mem_pool:
 * | page_metadata are (an array of struct page) | alignment pad | usable memory
 * |
 *
 * The usable memory: [pool_start_addr, pool_start_addr + pool_mem_size).
 */
void init_buddy(struct phys_mem_pool *pool, struct page *start_page,
                vaddr_t start_addr, unsigned long page_num)
{
        int order;
        int page_idx;
        struct page *page;

        // 初始化物理内存池的锁
        BUG_ON(lock_init(&pool->buddy_lock) != 0);

        /* Init the physical memory pool. */
        // 初始化内存池基本信息
        pool->pool_start_addr = start_addr;
        pool->page_metadata = start_page;
        pool->pool_mem_size = page_num * BUDDY_PAGE_SIZE;
        /* This field is for unit test only. */
        pool->pool_phys_page_num = page_num;

        /* Init the free lists */
        // 初始化空闲链表
        for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
                // 将每个order的空闲页面数量nr_free初始化为0
                pool->free_lists[order].nr_free = 0;
                // 初始化每个order的空闲链表头free_list
                init_list_head(&(pool->free_lists[order].free_list));
        }

        /* Clear the page_metadata area. */
        // 清零页面元数据
        memset((char *)start_page, 0, page_num * sizeof(struct page));

        /* Init the page_metadata area. */
        // 初始化每个页面的元数据
        for (page_idx = 0; page_idx < page_num; ++page_idx) {
                // 设置每个页面的初始状态
                // 分配状态为已分配，order为0
                // pool指向当前物理内存池
                page = start_page + page_idx;
                page->allocated = 1;
                page->order = 0;
                page->pool = pool;
        }

        /* Put each physical memory page into the free lists. */
        // 将每个物理页面放入空闲链表
        for (page_idx = 0; page_idx < page_num; ++page_idx) {
                page = start_page + page_idx;
                buddy_free_pages(pool, page);
        }
}

/**
 * 伙伴系统的内存分配功能
 * @param pool 物理内存池
 * @param order 指定的order开始查找可用的内存块
 */
struct page *buddy_get_pages(struct phys_mem_pool *pool, int order)
{
        int cur_order;
        struct list_head *free_list;
        struct page *page = NULL;

        if (unlikely(order >= BUDDY_MAX_ORDER)) {
                kwarn("ChCore does not support allocating such too large "
                      "continuous physical memory\n");
                return NULL;
        }

        lock(&pool->buddy_lock);

        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Find a chunk that satisfies the order requirement
         * in the free lists, then split it if necessary.
         */
        for (cur_order = order; cur_order < BUDDY_MAX_ORDER; cur_order++) {
                free_list = &pool->free_lists[cur_order].free_list;
                if (!list_empty(free_list)) {
                        /* Found a suitable block, remove it from free list */
                        page = list_entry(free_list->next, struct page, node);
                        list_del(&page->node);
                        pool->free_lists[cur_order].nr_free--;

                        /* If we found a larger block than needed, split it */
                        if (cur_order > order) {
                                page = split_chunk(pool, order, page);
                        } else {
                                page->allocated = 1;
                                page->order = order;
                        }

                        goto out;
                }
        }

        /* LAB 2 TODO 1 END */
out: __maybe_unused
        unlock(&pool->buddy_lock);
        return page;
}

/**
 * 将一个页面释放回伙伴系统的空闲链表中,
 * 并尝试与相邻的伙伴块合并以形成更大的空闲块
 * @param pool 物理内存池
 * @param page 要释放的页面
 */
void buddy_free_pages(struct phys_mem_pool *pool, struct page *page)
{
        int order;
        struct list_head *free_list;
        struct page *buddy;
        unsigned long page_idx, buddy_idx;
        lock(&pool->buddy_lock);

        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Merge the chunk with its buddy and put it into
         * a suitable free list.
         */
        /* 标记页面为未分配 */
        page->allocated = 0;

        /* 尝试合并块 */
        page = merge_chunk(pool, page);
        order = page->order;

        /* 将最终块放入对应order的空闲链表 */
        free_list = &pool->free_lists[order].free_list;
        list_add(&page->node, free_list);
        pool->free_lists[order].nr_free++;
        /* LAB 2 TODO 1 END */

        unlock(&pool->buddy_lock);
}

void *page_to_virt(struct page *page)
{
        vaddr_t addr;
        struct phys_mem_pool *pool = page->pool;

        BUG_ON(pool == NULL);

        /* page_idx * BUDDY_PAGE_SIZE + start_addr */
        addr = (page - pool->page_metadata) * BUDDY_PAGE_SIZE
               + pool->pool_start_addr;
        return (void *)addr;
}

struct page *virt_to_page(void *ptr)
{
        struct page *page;
        struct phys_mem_pool *pool = NULL;
        vaddr_t addr = (vaddr_t)ptr;
        int i;

        /* Find the corresponding physical memory pool. */
        for (i = 0; i < physmem_map_num; ++i) {
                if (addr >= global_mem[i].pool_start_addr
                    && addr < global_mem[i].pool_start_addr
                                       + global_mem[i].pool_mem_size) {
                        pool = &global_mem[i];
                        break;
                }
        }

        if (pool == NULL) {
                kdebug("invalid pool in %s", __func__);
                return NULL;
        }

        page = pool->page_metadata
               + (((vaddr_t)addr - pool->pool_start_addr) / BUDDY_PAGE_SIZE);
        return page;
}

unsigned long get_free_mem_size_from_buddy(struct phys_mem_pool *pool)
{
        int order;
        struct free_list *list;
        unsigned long current_order_size;
        unsigned long total_size = 0;

        for (order = 0; order < BUDDY_MAX_ORDER; order++) {
                /* 2^order * 4K */
                current_order_size = BUDDY_PAGE_SIZE * (1 << order);
                list = pool->free_lists + order;
                total_size += list->nr_free * current_order_size;

                /* debug : print info about current order */
                kdebug("buddy memory chunk order: %d, size: 0x%lx, num: %d\n",
                       order,
                       current_order_size,
                       list->nr_free);
        }
        return total_size;
}

unsigned long get_total_mem_size_from_buddy(struct phys_mem_pool *pool)
{
        return pool->pool_mem_size;
}
