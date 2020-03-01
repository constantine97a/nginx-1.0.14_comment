
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * 进程间的互斥锁基本上实现方式是两种，、
 * #1 进程间的共享内存
 * #2 使用文件锁的方式进程
 */
typedef struct {
    u_char      *addr;
    size_t       size;
    ngx_str_t    name;
    ngx_log_t   *log;
    ngx_uint_t   exists;   /* unsigned  exists:1;  */
} ngx_shm_t;

/**
 * 创建共享内存
 * @param shm
 * @return
 */
ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
/**
 * 释放共享内存
 * @param shm
 */
void ngx_shm_free(ngx_shm_t *shm);


#endif /* _NGX_SHMEM_H_INCLUDED_ */
