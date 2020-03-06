
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_TIMES_H_INCLUDED_
#define _NGX_TIMES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * ngx缓存在内存的时间结构，如果需要更新ngnix内部的时间只需要更新这个，
 * 除了ngx_time_t的结构体外，ngnix定义了许多全局变量
 */
typedef struct {
    time_t      sec;
    ngx_uint_t  msec;
    ngx_int_t   gmtoff;
} ngx_time_t;

/**
 * 初始化进程中的缓存的时间变量，同时会gettimeofday刷新缓存
 */
void ngx_time_init(void);
void ngx_time_update(void);
void ngx_time_sigsafe_update(void);
u_char *ngx_http_time(u_char *buf, time_t t);
u_char *ngx_http_cookie_time(u_char *buf, time_t t);
void ngx_gmtime(time_t t, ngx_tm_t *tp);

time_t ngx_next_time(time_t when);
#define ngx_next_time_n      "mktime()"


extern volatile ngx_time_t  *ngx_cached_time;

#define ngx_time()           ngx_cached_time->sec
#define ngx_timeofday()      (ngx_time_t *) ngx_cached_time

extern volatile ngx_str_t    ngx_cached_err_log_time;
extern volatile ngx_str_t    ngx_cached_http_time;
extern volatile ngx_str_t    ngx_cached_http_log_time;
extern volatile ngx_str_t    ngx_cached_http_log_iso8601;

/*
 * milliseconds elapsed since epoch and truncated to ngx_msec_t,
 * used in event timers
 */
/**
 * 当前的毫秒数，从1970年开始的毫秒数
 */
extern volatile ngx_msec_t  ngx_current_msec;


#endif /* _NGX_TIMES_H_INCLUDED_ */
