
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

// 使用三个数组的原因是，nginx把http配置设为http/server/location三个层次
/**
 * 在核心结构体ngx_cycle_t的conf_ctx成员指向的指针数组中，第7个指针由ngx_http_module模块使用
 * （ngx_http_module模块的index序号为6，由于由0开始，所以它在ngx_modules数组中排行第7。在存放全局配置结构体的conf_ctx数组中，第7个成员指向ngx_http_module模块），
 * 这个指针设置为指向解析http{}块时生成的ngx_http_conf_ctx_t结构体，
 * 而ngx_http_conf_ctx_t的3个成员则分别指向新分配的3个指针数组.
 */
typedef struct {
    /**
     * 指向一个指针数组，数组中的每一个成员都是由所有的HTTP模块的create_main_conf方法创建
     * 他们存放着解析直属http{}块内的main级别的配置参数
     *
     */
    void        **main_conf;//数组，数组成员是void*，指向http模块的mainconf
    /**
     * 指向一个指针数组，数组中的每一个成员都是由所有的HTTP模块的create_svr_conf方法创建
     * 他们可能存放着main,srv,loc级别的配置项，这与当前的ngx_http_conf_ctx_t是在解析http{},server{}
     * 块时创建的有关
     */
    void        **srv_conf; //server域的存储数组
    /**
 * 指向一个指针数组，数组中的每一个成员都是由所有的HTTP模块的create_loc_conf方法创建
 * 他们可能存放着main,srv,loc级别的配置项，这与当前的ngx_http_conf_ctx_t是在解析http{},server{},location{]
 * 块时创建的有关
 */
    void        **loc_conf;// localtion域的存储数组
} ngx_http_conf_ctx_t;

//HTTP框架在读取,重载配置文件时定义了由ngx_http_module_t接口描述的8个阶段
//这8个阶段的调用顺序应该是：
/**
 * ngx_http_module_t接口完全是围绕着配置项来进行的
create_main_conf
create_srv_conf
create_loc_conf
preconfiguration
init_main_conf
merge_srv_conf
merge_loc_conf
postconfiguration
**/
typedef struct {
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);  //解析配置文件前回调
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf); //完成配置文件解析后回调

    /**
     * 创建用于存储HTTP全局配置项的结构体，该结构体的成员将保存只属于HTTP{}块的配置项参数，
     * 它会在解析Main配置项前调用
     * @param cf
     */
    void       *(*create_main_conf)(ngx_conf_t *cf);  //当需要创建数据结构用户存储main级别的全局配置项时候调用

    /**
     * 解析完main配置项后回调
     * @param cf
     * @param conf
     */
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf); //初始化main级别配置项

    /**
     * 创建用户存储可同时出现在main，src级别配置项的结构体，该结构体的成员与server配置是相关联的
     * @param cf
     */
    void       *(*create_srv_conf)(ngx_conf_t *cf); //当需要创建数据结构用户存储srv级别的全局配置项时候调用
    /**
     * create_srv_conf生成的结构所需要解析的配置项，可能同时出现在main，srv级别中，merge_srv_conf  可以将出现在
     * main级别中配置项值合并在srv级别配置中
     * @param cf
     * @param prev
     * @param conf
     */
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf); //srv覆盖策略

    void       *(*create_loc_conf)(ngx_conf_t *cf); //当需要创建数据结构用户存储loc级别的全局配置项时候调用
    /**
   * create_loc_conf生成的结构所需要解析的配置项，可能同时出现在main，srv级别中，merge_loc_conf可以将出现在
   * main级别中配置项值合并在srv级别配置中
   * @param cf
   * @param prev
   * @param conf
   */
    char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf); //loc覆盖策略
} ngx_http_module_t;

/**
 * 翻译成String就是HTTP
 */
#define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */

#define NGX_HTTP_MAIN_CONF        0x02000000
#define NGX_HTTP_SRV_CONF         0x04000000
#define NGX_HTTP_LOC_CONF         0x08000000
#define NGX_HTTP_UPS_CONF         0x10000000
#define NGX_HTTP_SIF_CONF         0x20000000
#define NGX_HTTP_LIF_CONF         0x40000000
#define NGX_HTTP_LMT_CONF         0x80000000


#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)


#define ngx_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


#define ngx_http_conf_get_module_main_conf(cf, module)                        \
    ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_http_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_http_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

/**
 * 如何由ngx_cycle_t核心结构体中找到main级别的配置结构体
 */
#define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_http_module.index] ?                                 \
        ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */