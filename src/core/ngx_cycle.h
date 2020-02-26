
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */
//²Î¿¼×ÊÁÏ£º
//http://blog.csdn.net/benbendy1984/article/details/6007313

#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     16384
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
};

/*
注意理解cycle,cycle就是周期的意思，对应着一次启动过程。也就是说，不论是新的nginx、reload还是热替换，nginx都会创建一个新的cycle启动对应。
*/
struct ngx_cycle_s {
    /*
     保存着所有模块存储配置项的结构体指针，
     它首先是一个数组，数组大小为ngx_max_module，正好与Nginx的module个数一样；
     每个数组成员又是一个指针，指向另一个存储着指针的数组，因此会看到void ****

    请见陶辉所著《深入理解Nginx-模块开发与架构解析》一书302页插图。
    另外，这个图也不错：http://img.my.csdn.net/uploads/201202/9/0_1328799724GTUk.gif
    */
    void                  ****conf_ctx; 
    // 内存池
    ngx_pool_t               *pool;     

    /*
    日志模块中提供了生成基本ngx_log_t日志对象的功能，这里的log实际上是在还没有执行ngx_init_cycle方法前，
    也就是还没有解析配置前，如果有信息需要输出到日志，就会暂时使用log对象，它会输出到屏幕。
    在ngx_init_cycle方法执行后，将会根据nginx.conf配置文件中的配置项，构造出正确的日志文件，此时会对log重新赋值。
    */
    ngx_log_t                *log;      
    /*
    由nginx.conf配置文件读取到日志文件路径后，将开始初始化error_log日志文件，由于log对象还在用于输出日志到屏幕，
    这时会用new_log对象暂时性地替代log日志，待初始化成功后，会用new_log的地址覆盖上面的log指针
    */
    ngx_log_t                 new_log; 

    /*
    对于poll，rtsig这样的时间模块，会以有效文件句柄数来预先建立这些ngx_connection_t结构体，
    以加速事件的收集，分发。这时files就会保存所有ngx_connection_t的指针组成的数组，
    files_n就是指针的总数，而文件句柄的值用来访问files数组成员
    */
    ngx_connection_t        **files;    

    // 可用连接池，与free_connection_n配合使用
    ngx_connection_t         *free_connections;
    // 可用连接池中连接的总数
    ngx_uint_t                free_connection_n;    

    /* 双向链表容器，元素类型是ngx_connection_t结构体，表示可重复使用连接队列 */
    ngx_queue_t               reusable_connections_queue;  

    // 动态数组，每个数组元素储存着ngx_listening_t成员，表示监听端口及相关的参数
    ngx_array_t               listening;        

    /*
    动态数组容器，它保存着nginx所有要操作的目录。如果有目录不存在，就会试图创建，而创建目录失败就会导致nginx启动失败。
    */
    ngx_array_t               pathes;           
    /*
    单链表容器，元素类型是ngx_open_file_t 结构体，它表示nginx已经打开的所有文件。事实上，nginx框架不会向open_files链表中添加文件。
    而是由对此感兴趣的模块向其中添加文件路径名，nginx框架会在ngx_init_cycle 方法中打开这些文件
    */
    ngx_list_t                open_files;       

    // 单链表容器，元素类型是ngx_shm_zone_t结构体，每个元素表示一块共享内存
    ngx_list_t                shared_memory;   

    // 当前进程中所有链接对象的总数，与connections成员配合使用
    ngx_uint_t                connection_n;    
    ngx_uint_t                files_n;     

    // 指向当前进程中的所有连接对象，与connection_n配合使用
    ngx_connection_t         *connections;   
    // 指向当前进程中的所有读事件对象，connection_n同时表示所有读事件的总数
    ngx_event_t              *read_events;   
    // 指向当前进程中的所有写事件对象，connection_n同时表示所有写事件的总数
    ngx_event_t              *write_events;  

    /*
    旧的ngx_cycle_t 对象用于引用上一个ngx_cycle_t 对象中的成员。例如ngx_init_cycle 方法，在启动初期，
    需要建立一个临时的ngx_cycle_t对象保存一些变量，再调用ngx_init_cycle 方法时就可以把旧的ngx_cycle_t 对象传进去，
    而这时old_cycle对象就会保存这个前期的ngx_cycle_t对象。
    */
    ngx_cycle_t              *old_cycle;    

    // 配置文件相对于安装目录的路径名称
    ngx_str_t                 conf_file;
    // nginx 处理配置文件时需要特殊处理的在命令行携带的参数，一般是-g 选项携带的参数
    ngx_str_t                 conf_param;      
    // nginx配置文件所在目录的路径
    ngx_str_t                 conf_prefix;
    //nginx安装目录的路径
    ngx_str_t                 prefix;
    // 用于进程间同步的文件锁名称
    ngx_str_t                 lock_file;
    // 使用gethostname系统调用得到的主机名
    ngx_str_t                 hostname;   
};
//[p] 保存nginx运行所需的基本参数
typedef struct {
     /**
      * 语法：daemon on|off;
      * 默认：daemon on;
      * 守护进程（daemon）是脱离终端并且在后台运行的进程。它脱离终端是为了避免进程执行过程中的信息在任何终端上显示，
      * 这样一来，进程也不会被任何终端所产生的信息所打断。
      * Nginx毫无疑问是一个需要以守护进程方式运行的服务，因此，默认都是以这种方式运行的。
      */
     ngx_flag_t               daemon;  //[p] 守护进程标志
     /**
      * 语法：master_process on|off;
      * 是以一个master进程管理多个worker进程的方式运行的，几乎所有的产品环境下，Nginx都以这种方式工作。
      * master+worker process
      * master进程监听信号,
      * master<----- socketpair --> worker process
      */
     ngx_flag_t               master;  //[p] master进程标志

     ngx_msec_t               timer_resolution;
     /** 语法：worker_processes number;
      * 默认：worker_processes 1;
      * 在master/worker运行方式下，定义worker进程的个数。在MSP的架构下，work process应该 核数相同。
      * 多worker进程可以充分利用多核系统架构，但若worker进程的数量多于CPU内核数，那么会增大进程间切换带来的消耗（Linux是抢占式内核）。
      * 一般情况下，用户要配置与CPU内核数相等的worker进程，一般情况下使用worker_cpu_affinity配置来绑定CPU内核。
      * 如果配置了ngx_set_cpu_affinity ，会在解析配置时候调用 ngx_set_cpu_affinity（受限于NGX_HAVE_SCHED_SETAFFINITY宏）
      * 绑定CPU 内核。
      * 如果有4颗CPU内核，就可以进行如下配置
      * worker_processes  4;
      * worker_cpu_affinity 1000 0100 0010 0001;
      * worker_cpu_affinity配置仅对Linux操作系统有效。Linux操作系统使用sched_setaffinity()系统调用实现这个功能。
      * 在启动worker process时候调用sched_setaffinity()进行CPU粘滞。
      */
     ngx_int_t                worker_processes;    //[p] worker进程的数量
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile;
     ngx_int_t                rlimit_sigpending;

     /**
      * 在Linux系统中，当进程发生错误或收到信号而终止时，系统会将进程执行时的内存内容（核心映像）写入一个文件（core文件），
      * 以作为调试之用，这就是所谓的核心转储（core dumps）。
      * 当Nginx进程出现一些非法操作（如内存越界）导致进程直接被操作系统强制结束时，会生成核心转储core文件，
      * 可以从core文件获取当时的堆栈、寄存器等信息，从而帮助我们定位问题。但这种core文件中的许多信息不一定是用户需要的，
      * 如果不加以限制，那么可能一个core文件会达到几GB，这样随便coredumps几次就会把磁盘占满，
      * 引发严重问题。通过worker_rlimit_core配置可以限制core文件的大小，从而有效帮助用户定位问题。
      * 限制coredump核心转储文件的大小
      */
     off_t                    rlimit_core;

     int                      priority;

     ngx_uint_t               cpu_affinity_n;
     u_long                  *cpu_affinity;
    //Nginx worker进程运行的用户及用户组,默认是user nobody nobody;
     char                    *username;
     ngx_uid_t                user;                 /* user ID */  
     ngx_gid_t                group;                /* group ID*/ 

     /**
      * 这个配置项的唯一用途就是设置coredump文件所放置的目录，协助定位问题。
      * 因此，需确保worker进程有权限向working_directory指定的目录中写入文件
      */
     ngx_str_t                working_directory;
     /**
      * ngx_event 模块中 ngx_event_conf_t 中的accept_mutex *（可能）*需要这个lock文件，如果accept锁关闭，lock_file配置完全不生效，
      * 如果打开了accept锁，并且由于编译程序、操作系统架构等因素导致Nginx不支持原子锁，这时才会用文件锁实现accept锁。
      * 否则应该是使用系统提供的跨进程的Mutex.
      * 在基于i386、AMD64、Sparc64、PPC64体系架构的操作系统上，若使用GCC、Intel C++、SunPro
      * C++编译器来编译Nginx，则可以肯定这时的Nginx是支持原子锁的，
      * 因为Nginx会利用CPU的特性并用汇编语言来实现它（可以参考14.3节x86架构下原子操作的实现）。
      * 这时的lock_file配置是没有意义的。
      */
     ngx_str_t                lock_file;

     ngx_str_t                pid;
     ngx_str_t                oldpid;				

     ngx_array_t              env;
     char                   **environment;

#if (NGX_THREADS)
     ngx_int_t                worker_threads;
     size_t                   thread_stack_size;
#endif

} ngx_core_conf_t;


typedef struct {
     ngx_pool_t              *pool;   /* pcre's malloc() pool */
} ngx_core_tls_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
u_long ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_quiet_mode;
#if (NGX_THREADS)
extern ngx_tls_key_t          ngx_core_tls_key;
#endif


#endif /* _NGX_CYCLE_H_INCLUDED_ */
