
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_SENDFILE           2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_BEFORE             2


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


typedef struct {
    union {
        struct sockaddr        sockaddr;
        struct sockaddr_in     sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6    sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un     sockaddr_un;
#endif
        u_char                 sockaddr_data[NGX_SOCKADDRLEN];
    } u;

    socklen_t                  socklen;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                   ipv6only:2;
#endif

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t                 deferred_accept;
#endif

    u_char                     addr[NGX_SOCKADDR_STRLEN + 1];
} ngx_http_listen_opt_t;

//这个结构是定义了HTTP模块处理用户请求的11个阶段
/**
 * 这些phase按照先后顺序执行，只有在rewrite之后流程会重新跳转到NGX_HTTP_FIND_CONFIG_PHASE。
 * 其中，只有7个phase可以注册handler以定制处理过程，其他的只有一个固定的handler:
 * NGX_HTTP_POST_READ_PHASE
* NGX_HTTP_SERVER_REWRITE_PHASE,
* NGX_HTTP_REWRITE_PHASE,
* NGX_HTTP_PREACCESS_PHASE,
* NGX_HTTP_ACCESS_PHASE,
* NGX_HTTP_CONTENT_PHASE,
*NGX_HTTP_LOG_PHASE
 */
typedef enum {
    //在接收到完整的HTTP头部后处理的HTTP阶段
    NGX_HTTP_POST_READ_PHASE = 0, // 读取请求

    //在还没有查询到URI匹配的location前，这时rewrite重写URL也作为一个独立的HTTP阶段
    NGX_HTTP_SERVER_REWRITE_PHASE, //server级别的rewrite

    //根据URI寻找匹配的location，这个阶段只能由ngx_http_core_module模块实现，不建议其他HTTP模块重新定义这一阶段的行为
    NGX_HTTP_FIND_CONFIG_PHASE,//根据uri查找location

    //在查询到URI匹配的location之后的rewrite重写URL阶段
    NGX_HTTP_REWRITE_PHASE,//localtion级别的rewrite

    //用于在rewrite重写URL后重新跳到NGX_HTTP_FIND_CONFIG_PHASE阶段，防止错误的nginx.conf配置导致死循环
    // 这一阶段只有ngx_http_core_module处理，如果一个请求超过10次重定位，认为出现了死循环，
    //这时，NGX_HTTP_POST_REWRITE_PHASE会向用户返回500，表示服务器内部错误。
    NGX_HTTP_POST_REWRITE_PHASE,//server、location级别的rewrite都是在这个phase进行收尾工作的

    //处理NGX_HTTP_ACCESS_PHASE阶段前
    NGX_HTTP_PREACCESS_PHASE,//粗粒度的access

    //让HTTP模块判断是否允许这个请求访问NGINX服务器
    NGX_HTTP_ACCESS_PHASE,//细粒度的access，比如权限验证、存取控制

    //当NGX_HTTP_ACCESS_PHASE阶段中HTTP模块的handler返回不允许访问的错误码的时候，
    //这个阶段负责构造拒绝服务的用户相应
    NGX_HTTP_POST_ACCESS_PHASE,//根据上述两个phase得到access code进行操作

    //这个阶段完全是try_files配置项设立的。当HTTP请求访问静态文件资源的时候，try_files配置项
    //可以使这个请求顺序的访问多个静态文件资源。
    NGX_HTTP_TRY_FILES_PHASE, //实现try_files指令

    //用于处理HTTP请求内容的阶段。这个是大部分HTTP模块最喜欢介入的阶段。
    NGX_HTTP_CONTENT_PHASE,//生成http响应

    //处理完请求后记录日志的阶段。它是用来记录日志的
    NGX_HTTP_LOG_PHASE//log模块
} ngx_http_phases;

typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;

/**
 *   定义了checker方法的函数原型
 */
// 一个HTTP处理阶段中的checker检查方法，仅可以由HTTP框架实现，以此控制HTTP请求的处理流程
typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

/**
 * 一个http{}块解析完毕后将会根据nginx.conf中的配置产生由ngx_http_phase_handler_t组成的数组，
 * 在处理HTTP请求时，一般情况下这些阶段是顺序向后执行的，但ngx_http_phase_handler_t中的next成员使得它们也可以非顺序执行。
 */
struct ngx_http_phase_handler_s {
    /**
    在处理到某一个HTTP阶段时，HTTP框架将会在checker方法已实现的前提下首先调用checker方法来处理请求，
     而不会直接调用任何阶段汇总的handler方法。
    只有在checker方法中才会去调用handler方法。
     因此，事实上所有的checker方法都是由框架中的ngx_http_core_module模块实现的，且普通的HTTP模块
    无法重定义checker方法。
    */
    /* 执行校验，并调用handler函数，同一个phase的handler的checker相同 */
    ngx_http_phase_handler_pt  checker;

    /**
       除ngx_http_core_module模块以外的HTTP模块，只能通过定义handler方法才能介入某一个HTTP处理阶段以处理请求
     * handler函数指针, ngx_http_request.h line#380
     */
    ngx_http_handler_pt        handler;

    /**
     * 将要执行的下一个HTTP处理阶段的序号
    next的设计使得处理阶段不必按照顺序依次执行，既可以向后跳跃数个阶段继续执行，也可以跳跃到之前曾经执行过的某个阶段重新执行。
    通常，next表示下一个处理阶段中的第一个ngx_http_phase_handler_t处理方法
    */
    /*
    * 指向下一个phase的第一个handler在ngx_http_core_main_conf_t->phase_engine.handlers数组中的下标
    *
    */
    ngx_uint_t                 next;
};

/**
 * 一个http{}块解析完毕后将会根据nginx.conf中的配置产生由ngx_http_phase_handler_t组成的数组，
 * 在处理HTTP请求时，一般情况下这些阶段是顺序向后执行的，但ngx_http_phase_handler_t中的next成员使得它们也可以非顺序执行。
 * ngx_http_phase_engine_t结构体就是所有ngx_http_phase_handler_t组成的数组,
 *
 * ngx_http_phase_engine_t结构体是保存在全局的ngx_http_core_main_conf_t.
 */
 /**
  *   ngx_http_core_main_conf_t的phase_engine字段表示phase的执行引擎，它会把所有的phase handler组织成数组，
  * 元素是ngx_http_phase_handler_t。phase_engine会根据phases数组中注册的handler进行初始化
  */
typedef struct {
    /*
    handlers是由ngx_http_phase_handler_t构成的数组首地址，它表示一个请求可能经历的酥油ngx_http_handler_pt处理方法
    */
    ngx_http_phase_handler_t  *handlers;

    /*
    表示NGC_HTTP_REWRITE_PHASE阶段第一个ngx_http_phase_handler_t处理方法在handlers数组中的序号，
    用于在执行HTTP请求的任何阶段中快速跳转到NGX_HTTP_SERVER_REWRITE_PHASE阶段处理请求
    */
    ngx_uint_t                 server_rewrite_index;

    /*
    表示NGC_HTTP_REWRITE_PHASE阶段第一个ngx_http_phase_handler_t处理方法在handlers数组中的序号，
    用于在执行HTTP请求的任何阶段中快速跳转到NGX_HTTP_SERVER_REWRITE_PHASE阶段处理请求
    */
    ngx_uint_t                 location_rewrite_index;
} ngx_http_phase_engine_t;

// 该结构用来存储每个阶段的可用的处理函数
typedef struct {
    ngx_array_t              handlers; // 实质上是一个动态数组
} ngx_http_phase_t;

/**
 * HTTP全局配置项是基础，管理server、location
 * 等配置块时取决于ngx_http_core_module模块出现在main级别下存储全局配置项的ngx_http_core_main_conf_t结构体
 */
typedef struct {
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

    /**
     * phase_engine控制运行过程中一个HTTP请求所要经过的HTTP处理阶段,
     * 它将配合ngx_http_request_t结构体中的phase_handler成员使用（phase_handler指定了当前请求应当执行哪一个HTTP阶段）
     */
    ngx_http_phase_engine_t    phase_engine;

    ngx_hash_t                 headers_in_hash;

    ngx_hash_t                 variables_hash;

    ngx_array_t                variables;       /* ngx_http_variable_t */
    ngx_uint_t                 ncaptures;
    /**
     * 控制server name 散列桶总数
     * 语法：server_names_hash_max_size size;默认：server_names_hash_max_size 512;配置块：http、server、location
     * server_names_hash_max_size会影响散列表的冲突率。
     * server_names_hash_max_size越大，消耗的内存就越多，但散列key的冲突率则会降低，检索速度也更快
     * 。server_names_hash_max_size越小，消耗的内存就越小，但散列key的冲突率可能增高。
     */
    ngx_uint_t                 server_names_hash_max_size;
    /**
     * 语法：server_names_hash_bucket_size size;
     * 默认：server_names_hash_bucket_size 32|64|128;
     * 配置块：http、server、location
     * 为了提高快速寻找到相应server name的能力，Nginx使用散列表来存储servername
     * server_names_hash_bucket_size设置了每个散列桶占用的内存大小
     */
    ngx_uint_t                 server_names_hash_bucket_size;

    ngx_uint_t                 variables_hash_max_size;
    ngx_uint_t                 variables_hash_bucket_size;

    ngx_hash_keys_arrays_t    *variables_keys;

    ngx_array_t               *ports;

    ngx_uint_t                 try_files;       /* unsigned  try_files:1 */

    /**
     * phases数组更像一个临时变量，它实际上仅会在Nginx启动过程中用到，
     * 它的唯一使命是按照11个阶段的概念初始化phase_engine中的handlers数组，
     * 基本上11个phase，每一个phase 都会对应一个数组(ngx_http_phase_t动态数组)
     */
    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1]; //存放所有的phases,主要用于handle的注册,形成一个二维数组
} ngx_http_core_main_conf_t;


typedef struct {
    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    ngx_http_conf_ctx_t        *ctx;

    ngx_str_t                   server_name;

    size_t                      connection_pool_size;
    size_t                      request_pool_size;
    size_t                      client_header_buffer_size;

    ngx_bufs_t                  large_client_header_buffers;

    ngx_msec_t                  client_header_timeout;

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;

    ngx_http_virtual_names_t  *virtual_names;

#if (NGX_HTTP_SSL)
    ngx_uint_t                 ssl;   /* unsigned  ssl:1; */
#endif
} ngx_http_addr_conf_t;


typedef struct {
    in_addr_t                  addr;
    ngx_http_addr_conf_t       conf;
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_port_t;

/**
 * 每监听一个TCP端口，都将使用一个独立的ngx_http_conf_port_t结构体来表示
 */
typedef struct {
    // socket 地址家族
    ngx_int_t                  family;

    // 监听端口
    in_port_t                  port;

    // 监听的端口下对应着的所有ngx_http_conf_addr_t地址
    ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
} ngx_http_conf_port_t;

/**
 * Nginx是使用ngx_http_conf_addr_t结构体来表示一个对应着具体地址的监听端口的.
 * 一个ngx_http_conf_port_t将会对应多个ngx_http_conf_addr_t，而ngx_http_conf_addr_t就是以动态数组的形式保存在addrs成员中的
 */
typedef struct {
    // 监听套接字的各种属性
    ngx_http_listen_opt_t      opt;

    // 完全匹配server name的散列表
    ngx_hash_t                 hash;
    // 通配符前置的散列表
    ngx_hash_wildcard_t       *wc_head;
    // 通配符后置的散列表
    ngx_hash_wildcard_t       *wc_tail;

#if (NGX_PCRE)
    // 下面的regex数组中元素的个数
    ngx_uint_t                 nregex;
    /*
    regex指向静态数组，其数组成员就是ngx_http_server_name_t 结构体，表示正则表达式及其配置与server{} 虚拟主机
    */
    ngx_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    // 该监听端口下对应的默认 server{} 虚拟主机
    ngx_http_core_srv_conf_t  *default_server;

    // servers 动态数组中的成员将指向ngx_http_core_srv_conf_t结构体
    /**
     * server数组将监听端口和server虚拟主机关联起来
     */
    ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t;


struct ngx_http_server_name_s {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
};


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_http_complex_value_t   value;
    ngx_str_t                  args;
} ngx_http_err_page_t;


typedef struct {
    ngx_array_t               *lengths;
    ngx_array_t               *values;
    ngx_str_t                  name;

    unsigned                   code:10;
    unsigned                   test_dir:1;
} ngx_http_try_file_t;


struct ngx_http_core_loc_conf_s {
    // location 的名称，即nginx.conf 中location后的表达式
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
#if (NGX_HTTP_DEGRADATION)
    unsigned      gzip_disable_degradation:2;
#endif
#endif

    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    /*
    指向所属location 块内ngx_http_conf_ctx_t 结构体中的loc_conf 指针数组，它保存着当前location块内所有HTTP模块
    create_loc_conf方法产生的结构体指针
    */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    ngx_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */
    size_t        limit_rate_after;        /* limit_rate_after */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_uint_t    keepalive_requests;      /* keepalive_requests */
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    ngx_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    sendfile;                /* sendfile */
#if (NGX_HAVE_FILE_AIO)
    ngx_flag_t    aio;                     /* aio */
#endif
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_flag_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

    ngx_array_t  *error_pages;             /* error_page */
    ngx_http_try_file_t    *try_files;     /* try_files */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    ngx_uint_t    open_file_cache_min_uses;
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    /*
    将同一个server块内多个表达location块的 ngx_http_core_loc_conf_t 结构体以及双向链表方式组合起来，
    该locations指针将指向ngx_http_location_queue_t 结构体
    */
    ngx_queue_t  *locations;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};


typedef struct {
    // queue将作为ngx_queue_t 双向链表容器，从而将ngx_http_location_queue_t 结构体连接起来
    ngx_queue_t                      queue;
    // 如果location中的字符串可以精确匹配（包括正则），exact将指向对应的ngx_http_core_loc_conf_t结构体，否则值为null
    ngx_http_core_loc_conf_t        *exact;

    // 如果location中的字符串无法精确匹配（包括自定义的通配符），inclusive将指向对应的ngx_http_core_loc_conf_t 结构体，否则值为null
    ngx_http_core_loc_conf_t        *inclusive;

    // 指向location的名称
    ngx_str_t                       *name;
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_http_location_queue_t;


struct ngx_http_location_tree_node_s {
    // 左子树
    ngx_http_location_tree_node_t   *left;
    // 右子树
    ngx_http_location_tree_node_t   *right;
    // 无法完全匹配的location组成的树
    ngx_http_location_tree_node_t   *tree;

    /*
    如果location对应的URI匹配字符串属于能够完全匹配的类型，则exact指向其对应的ngx_http_core_loc_conf_t结构体，否则为NULL空指针
    */
    ngx_http_core_loc_conf_t        *exact;

    /*
    如果location对应的URI匹配字符串属于无法完全匹配的类型，则inclusive指向其对应的ngx_http_core_loc_conf_t 结构体，否则为NULL空指针
    */
    ngx_http_core_loc_conf_t        *inclusive;

    // 自动重定向标志
    u_char                           auto_redirect;

    // name字符串的实际长度
    u_char                           len;

    // name指向location对应的URI匹配表达式
    u_char                           name[1];
};


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_try_files_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif


ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **sr,
    ngx_http_post_subrequest_t *psr, ngx_uint_t flags);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);


ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;


#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }
                                                                              \
#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
