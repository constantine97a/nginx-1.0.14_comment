/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_TEST_BUILD_EPOLL)

/* epoll declarations */

#define EPOLLIN        0x001
#define EPOLLPRI       0x002
#define EPOLLOUT       0x004
#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400
#define EPOLLERR       0x008
#define EPOLLHUP       0x010

#define EPOLLET        0x80000000
#define EPOLLONESHOT   0x40000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};

int epoll_create(int size)
{
    return -1;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#if (NGX_HAVE_FILE_AIO)

#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247
#define SYS_eventfd       323

typedef u_int  aio_context_t;

struct io_event {
    uint64_t  data;  /* the data field from the iocb */
    uint64_t  obj;   /* what iocb this event came from */
    int64_t   res;   /* result code for this event */
    int64_t   res2;  /* secondary result */
};


int eventfd(u_int initval)
{
    return -1;
}

#endif
#endif


typedef struct {
    /**
     *在调用epoll_wait时，第二个参数和第三个参数将闲置Linux最多一次返回多少事件，
     * 这个配置将作为参数传入到epoll_wait。
     * events是调用epoll_wait方法时传入的第3个参数maxevents，而第2个参数events数组的大小也是由它决定的,ngx_epoll_init初始化这个数组
     */
    ngx_uint_t  events;
    /**
     *
     */
    ngx_uint_t  aio_requests;
} ngx_epoll_conf_t;


static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_epoll_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);

/*
 * 处理已经完成的异步IO
 */	
#if (NGX_HAVE_FILE_AIO)
static void ngx_epoll_eventfd_handler(ngx_event_t *ev);
#endif

static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);

/**
 * ep是epoll对象的描述符
 */
static int                  ep = -1;
/**
 * 事件的数组
 */
static struct epoll_event  *event_list;
/**
 * events是上面说到的epoll_events配置项参数
 */
static ngx_uint_t           nevents;

#if (NGX_HAVE_FILE_AIO)

int                         ngx_eventfd = -1;
aio_context_t               ngx_aio_ctx = 0;

static ngx_event_t          ngx_eventfd_event;
static ngx_connection_t     ngx_eventfd_conn;

#endif

static ngx_str_t      epoll_name = ngx_string("epoll");

static ngx_command_t  ngx_epoll_commands[] = {

    { ngx_string("epoll_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, events),
      NULL },

    { ngx_string("worker_aio_requests"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, aio_requests),
      NULL },

      ngx_null_command
};

//ngx_epoll_model的 ngx_event_module_t接口实现
ngx_event_module_t  ngx_epoll_module_ctx = {
    &epoll_name,
    ngx_epoll_create_conf,               /* create configuration */
    ngx_epoll_init_conf,                 /* init configuration */

    /**
     * ngx_event_actions_t
     */
    {
        ngx_epoll_add_event,             /* add an event */
        ngx_epoll_del_event,             /* delete an event */
        ngx_epoll_add_event,             /* enable an event */
        ngx_epoll_del_event,             /* disable an event */
        ngx_epoll_add_connection,        /* add an connection */
        ngx_epoll_del_connection,        /* delete an connection */
        NULL,                            /* process the changes */
        /**
         * 实现了ngx_event_actions_t的process_event
         */
        ngx_epoll_process_events,        /* process the events */
        /**
         *  在ngx_event_process_init方法中，”初始化事件模块“阶段被调用
         */
        ngx_epoll_init,                  /* init the events */
        ngx_epoll_done,                  /* done the events */
    }
};

ngx_module_t  ngx_epoll_module = {
    NGX_MODULE_V1,
    &ngx_epoll_module_ctx,               /* module context */
    ngx_epoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_HAVE_FILE_AIO)

/*
 * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
 * as syscalls instead of libaio usage, because the library header file
 * supports eventfd() since 0.3.107 version only.
 *
 * Also we do not use eventfd() in glibc, because glibc supports it
 * since 2.8 version and glibc maps two syscalls eventfd() and eventfd2()
 * into single eventfd() function with different number of parameters.
 */

static int
io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}


static int
io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}


static int
io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,
    struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}


static void
ngx_epoll_aio_init(ngx_cycle_t *cycle, ngx_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

    ngx_eventfd = syscall(SYS_eventfd, 0);//获取用于通知异步IO完成的文件

    if (ngx_eventfd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "eventfd() failed");
        ngx_file_aio = 0;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", ngx_eventfd);

    n = 1;

    if (ioctl(ngx_eventfd, FIONBIO, &n) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

    if (io_setup(epcf->aio_requests, &ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "io_setup() failed");
        goto failed;
    }

    ngx_eventfd_event.data = &ngx_eventfd_conn;
    ngx_eventfd_event.handler = ngx_epoll_eventfd_handler;
    ngx_eventfd_event.log = cycle->log;
    ngx_eventfd_event.active = 1;
    ngx_eventfd_conn.fd = ngx_eventfd;
    ngx_eventfd_conn.read = &ngx_eventfd_event;
    ngx_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &ngx_eventfd_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, ngx_eventfd, &ee) != -1) {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

    if (io_destroy(ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "io_destroy() failed");
    }

failed:

    if (close(ngx_eventfd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    ngx_eventfd = -1;
    ngx_aio_ctx = 0;
    ngx_file_aio = 0;
}

#endif

/*


 struct epoll_event{
    __uint32_t events;
    epool_data_t data;
 }
 events的标记位
 epollin:可读
 epollout:可写
 epollrdhup:tcp连接的远程关闭或是半关闭链接
 epollpri:对应连接上有紧急数据需要读
 epollhup:

 */

//主要是完成epoll的相关初始化工作
/**
 * 完成ngx_epoll_module的初始化工作，主要包括调用epoll_create创建epoll对象
 * 创建event_list用于event_wait调用时传递内核态的事件（作为输出参数）
 */
static ngx_int_t
ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_epoll_conf_t  *epcf;
    //取得epoll模块的配置结构
    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);
    //ep是epoll模块定义的一个全局变量，初始化为-1
    if (ep == -1) {
        /**
         * 调用epoll_create 在内核中创建epoll对象,
         * cycle->connection_n / 2 参数会被忽略
        */
        ep = epoll_create(cycle->connection_n / 2);  //创一个epoll对象，容量为总连接数的一半

        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "epoll_create() failed");
            return NGX_ERROR;
        }

#if (NGX_HAVE_FILE_AIO)

        ngx_epoll_aio_init(cycle, epcf);

#endif
    }

    if (nevents < epcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }
        //event_list存储产生事件的数组
        event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    nevents = epcf->events;

    /**
     * 指明读写I/O的方法
     */
    ngx_io = ngx_os_io;

    /**
     * 设置ngx_event_actions的接口
     */
    ngx_event_actions = ngx_epoll_module_ctx.actions;//各种工具方法
/**
 * 默认采用ET模式来使用epoll,NGX_USE_CLEAR_EVENT，实际上是告诉nginx 使用ET 模式
 * 我们可以参见epoll_event（epoll的事件信息） 结构体，epoll_event中events的取值有如下：
 * EPOLLIN表示对应的链接上有数据可读
 * EPOLLOUT:对应连接可以写入数据发送
 * EPOLLRDHUP：表示连接的远程关闭或者半关闭状态
 * EPOLLPRI:对应的连接有紧急数据需要读
 *
 */
#if (NGX_HAVE_CLEAR_EVENT)
    /**
     * epoll添加这个标志，主要为了实现边缘触发，nginx默认使用边缘触发的机制
     */
    ngx_event_flags = NGX_USE_CLEAR_EVENT
#else
    ngx_event_flags = NGX_USE_LEVEL_EVENT  //水平触发
#endif
                      |NGX_USE_GREEDY_EVENT //io的时候，直到EAGAIN为止
                      |NGX_USE_EPOLL_EVENT; //epoll标志

    return NGX_OK;
}

/*
 * 退出事件驱动模块前调用
 * #释放ep描述符
 * #释放event_list数组
 */
static void
ngx_epoll_done(ngx_cycle_t *cycle)
{
    if (close(ep) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll close() failed");
    }

    ep = -1;

#if (NGX_HAVE_FILE_AIO)

    if (ngx_eventfd != -1) {

        if (io_destroy(ngx_aio_ctx) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "io_destroy() failed");
        }

        if (close(ngx_eventfd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "eventfd close() failed");
        }

        ngx_eventfd = -1;
    }

    ngx_aio_ctx = 0;

#endif

    ngx_free(event_list);

    event_list = NULL;
    nevents = 0;
}

/**
 * ngx_event_actions是在Nginx事件框架处理事件时封装的接口,
 * 从ngx_epoll_module_ctx结构体中可以看出，enable和add接口都是使用ngx_epoll_add_event方法实现的，
 * 而disable和del接口都是使用ngx_epoll_del_event方法实现的.
 *
 * @param ev
 * @param event
 * @param flags
 * @return
 */
static ngx_int_t
ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    /**
     *     event的标志位，分别代表单前的标志位event和前一阶段的标志位Pre
     */
    uint32_t             events, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    //每一个事件的data成员都存放着对应的ngx_connection_t 连接
    c = ev->data;

    events = (uint32_t) event;
/**
 * 判断是读事件还是写事件，决定events是EPOLLIN 还是EPOLLOUT。
 */
    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (NGX_READ_EVENT != EPOLLIN)
        events = EPOLLIN;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN;
#if (NGX_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD;
    }
/**
 *加入flags参数到events标志位中
 */

    ee.events = events | (uint32_t) flags;

    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }
    /**
     *给当前事件添加上active的标记
     */
    ev->active = 1;
#if 0
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NGX_OK;
}

/**
 * 删除事件
 * @param ev
 * @param event
 * @param flags
 * @return
 */
static ngx_int_t
ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicity the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        ev->active = 0;
        return NGX_OK;
    }

    c = ev->data;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    ev->active = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicity the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}

/*epoll事件驱动模型的实现*/
/**
 * 实现了ngx_event_actions_t的process_event，
 * 注意instance标志位的问题，首先instance标志位利用到了地址码的最后一位必然为0的特点，将Instance标志位存在事件的ngx_connection_t的地址上
 * 这样就能一次性的取出
 * instance标记为的作用为防止ABA的问题
 * 前面事件处理导致后续时间失效的问题。
 * 设第3个事件对应的ngx_connection_t连接中的fd套接字原先是50，
 * 处理第1个事件时把这个连接的套接字关闭了，同时置为–1，
 * 并且调用ngx_free_connection将该连接归还给连接池。
 * 在ngx_epoll_process_events方法的循环中开始处理第2个事件，恰好第2个事件是建立新连接事件，
 * 调用ngx_get_connection从连接池中取出的连接非常可能就是刚刚释放的第3个事件对应的连接。
 * 由于套接字50刚刚被释放，Linux内核非常有可能把刚刚释放的套接字50又分配给新建立的连接。
 * 因此，在循环中处理第3个事件时，这个事件就是过期的了！它对应的事件是关闭的连接，而不是新建立的连接。
 * @param cycle
 * @param timer
 * @param flags
 * @return
 */
static ngx_int_t
ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    int                events;
    uint32_t           revents;
    ngx_int_t          instance, i;
    ngx_uint_t         level;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev, **queue;
    ngx_connection_t  *c;

    /* NGX_TIMER_INFINITE == INFTIM */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %M", timer);
    //一开始就是等待事件，最长等待时间为timer；nginx为事件专门用红黑树维护了一个计时器
    /**
     * 调用epoll_wait获取事件，注意timer参数是在process_events调用的时候传入的，
     * events指返回的event数目
     */
    events = epoll_wait(ep, event_list, (int) nevents, timer);

    //如果events 为-1 error设置为ngx_errno
    err = (events == -1) ? ngx_errno : 0;

    /**
     * 当flags标志位指示要更新时间时，调动ngx_time_update更新时间，将时间缓存在一组全局变量中
     */
    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        ngx_time_update(); //执行一次时间更新，nginx将时间缓存到一组全局变量中，方便程序高效的获取事件
    }
    //处理wait错误
    if (err) {
        if (err == NGX_EINTR) {

            if (ngx_event_timer_alarm) {
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "epoll_wait() failed");
        return NGX_ERROR;
    }
    //wait返回事件数0，可能是timeout返回，也可能是非timeout返回，非timeout返回则是error
    if (events == 0) {
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return NGX_ERROR;
    }

    ngx_mutex_lock(ngx_posted_events_mutex);
    //循环开始处理收到的所有事件
    for (i = 0; i < events; i++) {
        /**
         * event_list[i]是指时间，ptr是connection的地址（ngx_connection_t）
         * 最后一位有特殊含义
         */
        c = event_list[i].data.ptr;

        instance = (uintptr_t) c & 1;
        /**
         * 32bit还是64bit机器，地址最后位都为0，将地址转化为正确形态
         */
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);


        rev = c->read;
        //获取读事件后，判断FD是否合法，或者时间是否过期
        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }
        //取得发生一个事件
        revents = event_list[i].events;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);
        //记录wait的错误返回状态
        if (revents & (EPOLLERR|EPOLLHUP)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll_wait() error on fd:%d ev:%04XD",
                           c->fd, revents);
        }

#if 0
        if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "strange epoll_wait() events fd:%d ev:%04XD",
                          c->fd, revents);
        }
#endif
        //该事件是一个读事件，并该连接上注册的读事件是active的
        if ((revents & (EPOLLERR|EPOLLHUP))
             && (revents & (EPOLLIN|EPOLLOUT)) == 0)
        {
            /*
             * if the error events were returned without EPOLLIN or EPOLLOUT,
             * then add these flags to handle the events at least in one
             * active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }
        /**
         * 读事件且事件表示连接是或者的
         */
        if ((revents & EPOLLIN) && rev->active) {
            /**
             * rev->accept表示是从listerning的connection中收到的rev事件
             */
            if ((flags & NGX_POST_THREAD_EVENTS) && !rev->accept) {
                rev->posted_ready = 1;

            } else {
                rev->ready = 1;
            }
            //事件放入到相应的队列中
            /**
             *读事件，首先判断是新链接时间还是普通事件，以决定把它加入到ngx_posted_accept_events，还是ngx_posted_events
             *这两个队列会在延迟进行处理
             */
            if (flags & NGX_POST_EVENTS) {
                queue = (ngx_event_t **) (rev->accept ?
                               &ngx_posted_accept_events : &ngx_posted_events);

                ngx_locked_post_event(rev, queue);

            } else {
                //调用读事件的处理函数
                rev->handler(rev);
            }
        }

        wev = c->write;

        if ((revents & EPOLLOUT) && wev->active) {

            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            if (flags & NGX_POST_THREAD_EVENTS) {
                wev->posted_ready = 1;

            } else {
                wev->ready = 1;
            }

            if (flags & NGX_POST_EVENTS) {
                ngx_locked_post_event(wev, &ngx_posted_events);

            } else {
                //调用写事件的事件处理函数
                wev->handler(wev);
            }
        }
    }

    ngx_mutex_unlock(ngx_posted_events_mutex);

    return NGX_OK;
}


#if (NGX_HAVE_FILE_AIO)

static void
ngx_epoll_eventfd_handler(ngx_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    ngx_err_t         err;
    ngx_event_t      *e;
    ngx_event_aio_t  *aio;
    struct io_event   event[64];
    struct timespec   ts;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

    n = read(ngx_eventfd, &ready, 8);

    err = ngx_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) {
        if (n == -1) {
            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    while (ready) {

        events = io_getevents(ngx_aio_ctx, 1, 64, event, &ts);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %l", events);

        if (events > 0) {
            ready -= events;

            for (i = 0; i < events; i++) {

                ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %uXL %uXL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

                e = (ngx_event_t *) (uintptr_t) event[i].data;

                e->complete = 1;
                e->active = 0;
                e->ready = 1;

                aio = e->data;
                aio->res = event[i].res;

                ngx_post_event(e, &ngx_posted_events);
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "io_getevents() failed");
        return;
    }
}

#endif


static void *
ngx_epoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_epoll_conf_t  *epcf;

    epcf = ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = NGX_CONF_UNSET;
    epcf->aio_requests = NGX_CONF_UNSET;

    return epcf;
}


static char *
ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_epoll_conf_t *epcf = conf;

    ngx_conf_init_uint_value(epcf->events, 512);
    ngx_conf_init_uint_value(epcf->aio_requests, 32);

    return NGX_CONF_OK;
}