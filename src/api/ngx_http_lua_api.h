
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_HTTP_LUA_API_H_INCLUDED_
#define _NGX_HTTP_LUA_API_H_INCLUDED_


#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <lua.h>
#include <stdint.h>


/* Public API for other Nginx modules */


#define ngx_http_lua_version  10012


enum {
    SHDICT_TNIL      = 0,   /* same as LUA_TNIL      */
    SHDICT_TBOOLEAN  = 1,   /* same as LUA_TBOOLEAN  */
    SHDICT_TNUMBER   = 3,   /* same as LUA_TNUMBER   */
    SHDICT_TSTRING   = 4,   /* same as LUA_TSTRING   */
    SHDICT_TLIST     = 5,
    SHDICT_TZSET     = 6,
    SHDICT_TUSERDATA = 7    /* same as LUA_TUSERDATA */
};


typedef struct {
    uint8_t         type;

    union {
        int         b; /* boolean */
        lua_Number  n; /* number */
        ngx_str_t   s; /* string or userdata */
    } value;

} ngx_http_lua_value_t;


lua_State *ngx_http_lua_get_global_state(ngx_conf_t *cf);

ngx_http_request_t *ngx_http_lua_get_request(lua_State *L);

ngx_int_t ngx_http_lua_add_package_preload(ngx_conf_t *cf, const char *package,
    lua_CFunction func);

ngx_int_t ngx_http_lua_shared_dict_get(ngx_shm_zone_t *shm_zone,
    u_char *key_data, size_t key_len, ngx_http_lua_value_t *value);

ngx_shm_zone_t *ngx_http_lua_find_zone(u_char *name_data, size_t name_len);

ngx_shm_zone_t *ngx_http_lua_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


/* shared dictionary api */

#define NGX_LUA_SHDICT_OK             (NGX_OK)
#define NGX_LUA_SHDICT_ERROR          (NGX_ERROR)
#define NGX_LUA_SHDICT_NOT_FOUND      (NGX_HTTP_NOT_FOUND)
#define NGX_LUA_SHDICT_EXISTS         (NGX_HTTP_CONFLICT)
#define NGX_LUA_SHDICT_BAD_VALUE_TYPE (NGX_HTTP_BAD_REQUEST)
#define NGX_LUA_SHDICT_NO_MEMORY      (NGX_HTTP_INSUFFICIENT_STORAGE)


typedef ngx_int_t (*get_fun_t)(ngx_http_lua_value_t value,
    uint32_t user_flags, int stale, void *userdata);

ngx_int_t ngx_http_lua_shdict_api_fun(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, get_fun_t fun, void *userdata);

ngx_int_t ngx_http_lua_shdict_api_get(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t *value);

ngx_int_t ngx_http_lua_shdict_api_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags);

ngx_int_t ngx_http_lua_shdict_api_safe_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags);

ngx_int_t ngx_http_lua_shdict_api_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags);

ngx_int_t ngx_http_lua_shdict_api_safe_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags);

ngx_int_t ngx_http_lua_shdict_api_replace(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags);

ngx_int_t ngx_http_lua_shdict_api_delete(ngx_shm_zone_t *shm_zone,
    ngx_str_t key);

ngx_int_t ngx_http_lua_shdict_api_zset(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_zget(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_http_lua_value_t *value);

typedef ngx_int_t (*fun_t)(ngx_str_t zkey, ngx_http_lua_value_t value);

ngx_int_t ngx_http_lua_shdict_api_zscan(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, fun_t fun, ngx_str_t lbound);

ngx_int_t ngx_http_lua_shdict_api_zrem(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey);


#endif /* _NGX_HTTP_LUA_API_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
