
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/***
 * 从内存池中创建n个元素的数组，元素大小为size创建一个新的数组对象，并返回这个对象。
 *注意事项: 由于使用ngx_palloc分配内存，数组在扩容时，旧的内存不会被释放，会造成内存的浪费。
 *因此，最好能提前规划好数组的容量，在创建或者初始化的时候一次搞定，避免多次扩容，造成内存浪费。
 * @param p 数组分配内存使用的内存池；
 * @param n 数组的初始容量大小，即在不扩容的情况下最多可以容纳的元素个数。
 * @param size 单个元素的大小，单位是字节。
 * @return
 */
ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    // 分配ngx_array_t数组管理结构的内存
    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    // 分配存放n个元素，单个元素大小为size的内存空间
    a->elts = ngx_palloc(p, n * size);
    if (a->elts == NULL) {
        return NULL;
    }

    a->nelts = 0;
    a->size = size;	// 元素大小
    a->nalloc = n;	// 数组容量
    a->pool = p;

    return a;
}

/***
 * 销毁数组，判断ngx_pool_data_t的last指针是否为元素的最后一个元素的地址
 * if So,
 * @param a
 */
void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;

    // 若内存池未使用内存地址等于数组最后元素的地址，则释放数组内存到内存池
    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }
    //如果内存池last地址等于数据Header的尾地址，释放数据内存在内存池
    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}

/*
首先判断　nalloc是否和nelts相等，即数组预先分配的空间已经满了，如果没满则计算地址直接返回指针
如果已经满了则先判断是否我们的pool中的当前链表节点还有剩余的空间，如果有则直接在当前的pool链表节点中分配内存，并返回
如果当前链表节点没有足够的空间则使用ngx_palloc重新分配一个2倍于之前数组空间大小的数组，然后将数据转移过来，并返回新地址的指针
*/
void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;

    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;

        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */
            //当前的内存是连续的，所以array的内存在当前的pool中推进一个元素的长度就能满足分配需要
            p->d.last += a->size;
            a->nalloc++;

        } else {
            /* allocate a new array */
            //尝试分配原来数组长度两倍大小的鼠标，并将数据的数据拷贝至新内存地址中，并只设定新内存地址，大小和额定长度
            new = ngx_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }
    //array的头指针+元素的大小*元素的个数
    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;
    //返回当前分配的内存地址
    return elt;
}


void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
