
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
    union {
        int         b; /* boolean */
        lua_Number  n; /* number */
        ngx_str_t   s; /* string or userdata */
    } value;

    int32_t user_flags;
    uint8_t type;
    u_char valid;
} ngx_http_lua_value_t;


#define MAX_SHDICT_QUEUE_VALUE_SIZE (32768)


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


void ngx_http_lua_shdict_lock(ngx_shm_zone_t *shm_zone);

void ngx_http_lua_shdict_unlock(ngx_shm_zone_t *shm_zone);

typedef ngx_int_t (*get_fun_t)(ngx_http_lua_value_t *value,
    int stale, void *userctx);

ngx_int_t ngx_http_lua_shdict_api_fun(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, get_fun_t fun, int64_t exptime, void *userctx);

ngx_int_t ngx_http_lua_shdict_api_fun_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, get_fun_t fun, int64_t exptime, void *userctx);

/* copying structure into value */
ngx_int_t ngx_http_lua_shdict_api_get(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t *value);

/* value contents the reference (string/userdata) to data */
ngx_int_t ngx_http_lua_shdict_api_get_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t *value);

lua_Number ngx_http_lua_shdict_api_incr(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, lua_Number inc, lua_Number def, int exptime);

lua_Number ngx_http_lua_shdict_api_incr_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, lua_Number inc, lua_Number def, int exptime);

ngx_int_t ngx_http_lua_shdict_api_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_set_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_safe_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_safe_set_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_add_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_safe_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_safe_add_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_replace(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_replace_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_delete(ngx_shm_zone_t *shm_zone,
    ngx_str_t key);

ngx_int_t ngx_http_lua_shdict_api_delete_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key);

ngx_int_t ngx_http_lua_shdict_api_expire(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t exptime);

ngx_int_t ngx_http_lua_shdict_api_expire_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t exptime);

ngx_int_t ngx_http_lua_shdict_api_ttl(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t *ttl);

ngx_int_t ngx_http_lua_shdict_api_ttl_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t *ttl);

/* zset */

ngx_int_t ngx_http_lua_shdict_api_zset(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_zset_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_http_lua_value_t value, int exptime);

/* copying structure into value */
ngx_int_t ngx_http_lua_shdict_api_zget(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_http_lua_value_t *value);

/* value contents the reference (string/userdata) to data */
ngx_int_t ngx_http_lua_shdict_api_zget_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_http_lua_value_t *value);

ngx_int_t ngx_http_lua_shdict_api_zadd(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_http_lua_value_t value, int exptime);

ngx_int_t ngx_http_lua_shdict_api_zadd_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_http_lua_value_t value, int exptime);

typedef ngx_int_t (*fun_t)(ngx_str_t zkey, ngx_http_lua_value_t *value,
    void *userctx);

ngx_int_t ngx_http_lua_shdict_api_zscan(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, fun_t fun, ngx_str_t lbound, void *userctx);

ngx_int_t ngx_http_lua_shdict_api_zscan_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, fun_t fun, ngx_str_t lbound, void *userctx);

ngx_int_t ngx_http_lua_shdict_api_zrem(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey);

ngx_int_t ngx_http_lua_shdict_api_zrem_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey);

ngx_int_t ngx_http_lua_shdict_api_zcard(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len);

ngx_int_t ngx_http_lua_shdict_api_zcard_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len);

/* queue */

ngx_int_t ngx_http_lua_shdict_api_rpush(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value);

ngx_int_t ngx_http_lua_shdict_api_rpush_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value);

ngx_int_t ngx_http_lua_shdict_api_lpush(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value);

ngx_int_t ngx_http_lua_shdict_api_lpush_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value);

ngx_int_t ngx_http_lua_shdict_api_rpop(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t *value);

ngx_int_t ngx_http_lua_shdict_api_rpop_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t *value);

ngx_int_t ngx_http_lua_shdict_api_lpop(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t *value);

ngx_int_t ngx_http_lua_shdict_api_lpop_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t *value);

ngx_int_t ngx_http_lua_shdict_api_llen(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len);

ngx_int_t ngx_http_lua_shdict_api_llen_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len);

#endif /* _NGX_HTTP_LUA_API_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
