
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>


typedef struct {
    int     signo;  //信号的编号
    char   *signame; //信号的字符串表现形式
    char   *name; //信号名称
    void  (*handler)(int signo); //信号处理函数
} ngx_signal_t;



static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);
static void ngx_signal_handler(int signo);
static void ngx_process_get_status(void);


int              ngx_argc;
char           **ngx_argv;
char           **ngx_os_argv;
/***
 * 当前操作的进程在ngx_processes中的下标
 */
ngx_int_t        ngx_process_slot;

ngx_socket_t     ngx_channel;
/**
 * ngx_processes中有意义的ngx_process_t 的元素的最大的Index
 */
ngx_int_t        ngx_last_process;
/***
 * ngx_processes数组，这个数组仅仅是给master进程使用的
 * master process通过这个对所有的work process 管理
 */
ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];
/**
 * 僵尸进程是指一个已经终止、但是其父进程尚未对其进行善后处理获取终止进程的有关信息的进程，这个进程被称为“僵尸进程”(zombie)。

怎样产生僵尸进程
        一个进程在调用exit命令结束自己的生命的时候，其实它并没有真正的被销毁，而是留下一个称为僵尸进程（Zombie）的数据结构（系统调用exit， 它的作用是使进程退出，但也仅仅限于将一个正常的进程变成一个僵尸进程，并不能将其完全销毁）。

        在Linux进程的状态中，僵尸进程是非常特殊的一种，它已经放弃了几乎所有内存空间，没有任何可执行代码，也不能被调度，仅仅在进程列表中保留一个位 置，记载该进程的退出状态等信息供其他进程收集。除此之外，僵尸进程不再占有任何内存空间。它需要它的父进程来为它收尸，如果他的父进程没安装 SIGCHLD 信号处理函数调用wait或waitpid()等待子进程结束，又没有显式忽略该信号，那么它就一直保持僵尸状态，如果这时父进程结束了， 那么init进程自动会接手这个子进程，为它收尸，它还是能被清除的。但是如果如果父进程是一个循环，不会结束，那么子进程就会一直保持僵尸状态，这就是 为什么系统中有时会有很多的僵尸进程。

怎么查看僵尸进程
        利用命令ps，可以看到有父进程ID为1的进程是孤儿进程；s(state)状态为Z的是僵尸进程。

注意：孤儿进程(orphan process)是尚未终止但已停止(相当于前台挂起)的进程，但其父进程已经终止，由init收养；而僵尸进程则是已终止的进程，其父进程不一定终止。

**怎样来清除僵尸进程
        改写父进程，在子进程死后要为它收尸。具体做法是接管SIGCHLD信号。子进程死后， 会发送SIGCHLD信号给父进程，父进程收到此信号后，执行 waitpid()函数为子进程收尸。这是基于这样的原理：就算父进程没有调用wait，内核也会向它发送SIGCHLD消息，尽管对的默认处理是忽略， 如果想响应这个消息，可以设置一个处理函数。
把父进程杀掉。父进程死后，僵尸进程成为"孤儿进程"，过继给1号进程init，init始终会负责清理僵尸进程，关机或重启后所有僵尸进程都会消失。
避免Zombie Process的方法
在SVR4中，如果调用signal或sigset将SIGCHLD的配置设置为忽略,则不会产生僵死子进程。另外,使用SVR4版的 sigaction,则可设置SA_NOCLDWAIT标志以避免子进程僵死。 Linux中也可使用这个，在一个程序的开始调用这个函数signal(SIGCHLD,SIG_IGN)。
调用fork两次。
用waitpid等待子进程返回。
 */
/**
 * 此处定义了所有nginx所支持的信号,从上文的资料可知，在master process中要注册sigchld信号的处理函数
 *
 */
ngx_signal_t  signals[] = {
    { ngx_signal_value(NGX_RECONFIGURE_SIGNAL),
      "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL),
      "reload",
      ngx_signal_handler },

    { ngx_signal_value(NGX_REOPEN_SIGNAL),
      "SIG" ngx_value(NGX_REOPEN_SIGNAL),
      "reopen",
      ngx_signal_handler },

    { ngx_signal_value(NGX_NOACCEPT_SIGNAL),
      "SIG" ngx_value(NGX_NOACCEPT_SIGNAL),
      "",
      ngx_signal_handler },

    { ngx_signal_value(NGX_TERMINATE_SIGNAL),
      "SIG" ngx_value(NGX_TERMINATE_SIGNAL),
      "stop",
      ngx_signal_handler },

    { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),
      "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),
      "quit",
      ngx_signal_handler },

    { ngx_signal_value(NGX_CHANGEBIN_SIGNAL),
      "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL),
      "",
      ngx_signal_handler },

    { SIGALRM, "SIGALRM", "", ngx_signal_handler },

    { SIGINT, "SIGINT", "", ngx_signal_handler },

    { SIGIO, "SIGIO", "", ngx_signal_handler },

    { SIGCHLD, "SIGCHLD", "", ngx_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", SIG_IGN },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },

    { 0, NULL, "", NULL }
};

/***
 * master进程通过调用ngx_spwan_process创建工作进程，其中proc指针指向工作进程要执行的具体函数
 * 函数的主要功能是：
 * 1 有一个ngx_processes全局数组，包含了所有的存货的子进程，这里会fork出来的子进程放入到相应的位置。并设置这个进程的相关属性。
   2 创建socketpair，并设置相关属性。
   3 在子进程中执行传递进来的函数。
   需要参考 ngx_process_t ,该类型封装process进程的基本信息
 * @param cycle
 * @param proc
 * @param data
 * @param name
 * @param respawn
 * @return
 */
ngx_pid_t
ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data,
    char *name, ngx_int_t respawn)
{
    /*
     * ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];
     * 全局的进程信息表
     *
     */
    u_long     on;
    ngx_pid_t  pid;
    //表示将要fork的子进程在ngx_process中的位置
    ngx_int_t  s;

    //如果传递进来的类型大于0,则就是已经确定这个进程已经退出，我们就可以直接确定slot
    if (respawn >= 0) {
        s = respawn;

    } else {
        //遍历ngx_processess，从而找到空闲的slot，从而等会fork完毕后,将子进程信息放入全局进程信息表的相应的slot
        for (s = 0; s < ngx_last_process; s++) {
            if (ngx_processes[s].pid == -1) {
                break;
            }
        }

        //到达最大进程限制报错
        if (s == NGX_MAX_PROCESSES) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          NGX_MAX_PROCESSES);
            return NGX_INVALID_PID;
        }
    }

    //如果类型为NGX_PROCESS_DETACHED，则说明是热代码替换(热代码替换也是通过这个函数进行处理的)，因此不需要新建socketpair
    if (respawn != NGX_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */
        //创建socketpair，并设置相关属性,用于进程间通信,nginx中使用socket进行进程间通信
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, ngx_processes[s].channel) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return NGX_INVALID_PID;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       ngx_processes[s].channel[0],
                       ngx_processes[s].channel[1]);
        
        //设置非阻塞模式
        if (ngx_nonblocking(ngx_processes[s].channel[0]) == -1) { //设置channel[0]非阻塞,ngx_nonblocking为ioctl系统调用的封装
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (ngx_nonblocking(ngx_processes[s].channel[1]) == -1) { //设置channel[1]非阻塞
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        //打开异步模式
        on = 1;
        if (ioctl(ngx_processes[s].channel[0], FIOASYNC, &on) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        //设置异步IO的所有者
        if (fcntl(ngx_processes[s].channel[0], F_SETOWN, ngx_pid) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        //当执行后关闭句柄
        if (fcntl(ngx_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        //设置当前子进程的句柄
        ngx_channel = ngx_processes[s].channel[1];

    } else {
        ngx_processes[s].channel[0] = -1;
        ngx_processes[s].channel[1] = -1;
    }

    //设置全局的ngx_process_slot
    ngx_process_slot = s;

	//创建子进程
    pid = fork();

    switch (pid) {

    case -1:
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "fork() failed while spawning \"%s\"", name);
        ngx_close_channel(ngx_processes[s].channel, cycle->log);
        return NGX_INVALID_PID;

    case 0:
        ngx_pid = ngx_getpid();
        //在子进程中执行传递进来的函数，即工作进程的具体工作
        proc(cycle, data);
        break;

    default:
        break;
    }

    // 回到父进程执行
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);

    ngx_processes[s].pid = pid;
    ngx_processes[s].exited = 0;

    ///如果大于0,则说明我们确定了重启的子进程，因此下面的初始化就用已死的子进程的就够了。
    if (respawn >= 0) {
        return pid;
    }
    ///开始初始化进程结构。
    ngx_processes[s].proc = proc;
    ngx_processes[s].data = data;
    ngx_processes[s].name = name;
    ngx_processes[s].exiting = 0;
	//根据传入的respawn标记对nginx当前的进程进行相关设置，比如执行函数，运行状态。。。
    ///设置相关状态。
    switch (respawn) {

    case NGX_PROCESS_NORESPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_SPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_DETACHED:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 1;
        break;
    }

    if (s == ngx_last_process) {
        ngx_last_process++;
    }

    return pid;
}


ngx_pid_t
ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
    return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name,
                             NGX_PROCESS_DETACHED);
}


static void
ngx_execute_proc(ngx_cycle_t *cycle, void *data)
{
    ngx_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}

//ngx_init_signals方法会初始化signals数组中所有的信号，ngx_init_signals其实是调用了sigaction方法注册信号的回调方法。
ngx_int_t
ngx_init_signals(ngx_log_t *log)
{
    ngx_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = sig->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "sigaction(%s) failed", sig->signame);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

//就目前nginx代码来看，子进程并没有往父进程发送任何消息，子进程之间也没有相互通信的逻辑，也许是因为nginx有其它一些更好的进程通信方式，
// 比如共享内存等，所以这种channel通信目前仅做为父进程往子进程发送消息使用，但由于有这个基础在这，如果未来要使用channel做这样的事情，的确是可以的。

//在nginx中，worker和master的交互，是通过流管道以及信号。
//而master与外部的交互是通过信号来进行的,这个函数就是master处理信号的程序。
/**
 * 主要作用是接收到signo
 * 判断是否是master process设置全局变量，在cycle循环中根据这些变量做动作
 * 判断是否是worker process 设置全部变脸，在worker的cycle循环中根据这些变量做动作
 * @param signo
 */
void
ngx_signal_handler(int signo)
{
    char            *action;//just for logging
    ngx_int_t        ignore;//flag for ignore signo
    ngx_err_t        err;
    ngx_signal_t    *sig;

    ignore = 0;

    err = ngx_errno;
    
    //得到当前的信号
    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
	//整个nginx源码中，仅此一处调用ngx_time_sigsafe_update函数，因此调用时间更新函数的频率很低
    ngx_time_sigsafe_update();

    action = "";

    //这里ngx_process在master和worker中赋值不同
    switch (ngx_process) {

    case NGX_PROCESS_MASTER:
    case NGX_PROCESS_SINGLE:
        switch (signo) {

        //quit信号
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        //终止信号
        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        //winch信号，停止接受accept
        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (ngx_daemonized) {
                ngx_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;

        //sighup信号用来reconfig
        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
            ngx_reconfigure = 1;
            action = ", reconfiguring";
            break;

        //用户信号，用来reopen
        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        //热代码替换
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
            if (getppid() > 1 || ngx_new_binary > 0) {
                /**
                 * getppid() return the parent process of currentId ,so if ppid >0 it means
                 * this is the latest new master process ,and old master may not shutdown(currently ,there are two master process)
                 * SO ignore 'USR2' Signal
                 */
                /**
                 * Ignore the signal in the new binary if its parent is
                 * not the init process, i.e. the old binary's process
                 * is still running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */
                /** 这里给出了详细的注释，更通俗一点来讲，就是说，进程现在是一个
                * master(新的master进程)，但是当他的父进程old master还在运行的话，
                * 这时收到了USR2信号，我们就忽略它，不然就成了新master里又要生成
                * master。。。另外一种情况就是，old master已经开始了生成新master的过程
                * 中，这时如果又有USR2信号到来，那么也要忽略掉。。。(不知道够不够通俗=.=)
                参考文档：http://blog.csdn.net/dingyujie/article/details/7192144
                */
                action = ", ignoring";
                ignore = 1;
                break;
            }

            //正常情况下，需要热代码替换，设置标志位
            ngx_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            ngx_sigalrm = 1;
            break;

        case SIGIO:
            ngx_sigio = 1;
            break;
        /**
         * 如果子进程发生退出，Linux内核会想父进程发送SIGCHLD进程，父进程需要调用wait或者waitpid或者显式的忽略该信号，子进程可能会一直
         * 出于僵尸状态
         */
        case SIGCHLD:
            ngx_reap = 1;
            break;
        }

        break;

    //worker的信号处理
    case NGX_PROCESS_WORKER:
    case NGX_PROCESS_HELPER:
        switch (signo) {

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (!ngx_daemonized) {
                break;
            }
            ngx_debug_quit = 1;
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            /**
             * 优雅的关闭,在ngx_worker_process_cycle检测使用
             */
            ngx_quit = 1;
            action = ", shutting down";
            break;

        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            /**
             * 强制关闭,在ngx_worker_process_cycle检测使用
             */
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            /**
             * 重新打开所有文件，在ngx_worker_process_cycle检测使用
             */
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "signal %d (%s) received%s", signo, sig->signame, action);

    if (ignore) {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }

    //最终如果信号是sigchld，我们收割僵尸进程(用waitpid)
    if (signo == SIGCHLD) {
        /***
         * 获得所有子进程状态
         *
         */
        ngx_process_get_status();
    }

    ngx_set_errno(err);
}

/**
 *
 * 调用ngx_process_get_status方法修改ngx_processes数组中所有子进程的状态,
 * （通过waitpid系统调用得到意外结束的子进程ID，然后遍历ngx_processes数组找到该子进程ID对应的ngx_process_t结构体，将其exited标志位置为1
 */
static void
ngx_process_get_status(void)
{
    int              status;
    char            *process;
    ngx_pid_t        pid;
    ngx_err_t        err;
    ngx_int_t        i;
    ngx_uint_t       one;

    one = 0;

    for ( ;; ) {
        /**
         * which process status is WHOHANG
         */
        pid = waitpid(-1, &status, WNOHANG);
        /**
         * 当pid返回O，退出循环
         */
        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = ngx_errno;

            if (err == NGX_EINTR) {
                continue;
            }

            if (err == NGX_ECHILD && one) {
                return;
            }

#if (NGX_SOLARIS || NGX_FREEBSD)

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process.
             *
             * When several processes exit at the same time FreeBSD may
             * erroneously call the signal handler for exited process
             * despite waitpid() may be already called for this process.
             */

            if (err == NGX_ECHILD) {
                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, err,
                              "waitpid() failed");
                return;
            }

#endif

            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                          "waitpid() failed");
            return;
        }


        if (ngx_accept_mutex_ptr) {

            /*
             * unlock the accept mutex if the abnormally exited process
             * held it
             */

            ngx_atomic_cmp_set(ngx_accept_mutex_ptr, pid, 0);
        }


        one = 1;
        process = "unknown process";
        //更新对应的worker_processes中的状态信息
        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_processes[i].pid == pid) {
                ngx_processes[i].status = status;
                ngx_processes[i].exited = 1;
                process = ngx_processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d",
                          process, pid, WTERMSIG(status));
#endif

        } else {
            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited with fatal code %d "
                          "and cannot be respawned",
                          process, pid, WEXITSTATUS(status));
            ngx_processes[i].respawn = 0;
        }
    }
}


void
ngx_debug_point(void)
{
    ngx_core_conf_t  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    switch (ccf->debug_points) {

    case NGX_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case NGX_DEBUG_POINTS_ABORT:
        ngx_abort();
    }
}

/* 信号处理，根据name到ngx_signal_t的名字中去匹配，找到信号，然后通过kill向master发送消息。*/
ngx_int_t
ngx_os_signal_process(ngx_cycle_t *cycle, char *name, ngx_int_t pid)
{
    ngx_signal_t  *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        if (ngx_strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) != -1) {
                return 0;
            }

            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "kill(%P, %d) failed", pid, sig->signo);
        }
    }

    return 1;
}
