
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_shdict.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_api.h"


typedef void (*err_fun_t)(void *userdata, const char *fmt, ...);


static int ngx_http_lua_shdict_set(lua_State *L);
static int ngx_http_lua_shdict_safe_set(lua_State *L);
static int ngx_http_lua_shdict_get(lua_State *L);
static int ngx_http_lua_shdict_get_stale(lua_State *L);
static ngx_int_t ngx_http_lua_shdict_api_fun_impl(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, get_fun_t fun, err_fun_t errlog, int get_stale, void *userdata);
static int ngx_http_lua_shdict_get_helper(lua_State *L, int get_stale);
static int ngx_http_lua_shdict_expire(ngx_http_lua_shdict_ctx_t *ctx,
    ngx_uint_t n);
static ngx_int_t ngx_http_lua_shdict_lookup(ngx_shm_zone_t *shm_zone,
    ngx_uint_t hash, u_char *kdata, size_t klen,
    ngx_http_lua_shdict_node_t **sdp);
static int ngx_http_lua_shdict_lua_set_helper(lua_State *L, int flags);
static int ngx_http_lua_shdict_add(lua_State *L);
static int ngx_http_lua_shdict_safe_add(lua_State *L);
static int ngx_http_lua_shdict_replace(lua_State *L);
static int ngx_http_lua_shdict_incr(lua_State *L);
static int ngx_http_lua_shdict_delete(lua_State *L);
static int ngx_http_lua_shdict_flush_all(lua_State *L);
static int ngx_http_lua_shdict_flush_expired(lua_State *L);
static int ngx_http_lua_shdict_get_keys(lua_State *L);
static int ngx_http_lua_shdict_lpush(lua_State *L);
static int ngx_http_lua_shdict_rpush(lua_State *L);
static int ngx_http_lua_shdict_push_helper(lua_State *L, int flags);
static int ngx_http_lua_shdict_lpop(lua_State *L);
static int ngx_http_lua_shdict_rpop(lua_State *L);
static int ngx_http_lua_shdict_pop_helper(lua_State *L, int flags);
static int ngx_http_lua_shdict_llen(lua_State *L);
static int ngx_http_lua_shdict_fun(lua_State *L);
static int ngx_http_lua_shared_dict_ttl(lua_State *L);
static int ngx_http_lua_shared_dict_expire(lua_State *L);
static int ngx_http_lua_shared_dict_capacity(lua_State *L);
#    if nginx_version >= 1011007
static int ngx_http_lua_shared_dict_free_space(lua_State *L);
#    endif
static int ngx_http_lua_shdict_zset(lua_State *L);
static int ngx_http_lua_shdict_zrem(lua_State *L);
static int ngx_http_lua_shdict_zgetall(lua_State *L);
static int ngx_http_lua_shdict_zget(lua_State *L);
static int ngx_http_lua_shdict_zcard(lua_State *L);
static int ngx_http_lua_shdict_zscan(lua_State *L);

static ngx_inline ngx_shm_zone_t *ngx_http_lua_shdict_get_zone(lua_State *L,
                                                               int index);


#define NGX_HTTP_LUA_SHDICT_ADD         0x0001
#define NGX_HTTP_LUA_SHDICT_REPLACE     0x0002
#define NGX_HTTP_LUA_SHDICT_SAFE_STORE  0x0004


#define NGX_HTTP_LUA_SHDICT_LEFT        0x0001
#define NGX_HTTP_LUA_SHDICT_RIGHT       0x0002


enum {
    SHDICT_USERDATA_INDEX = 1,
};


static ngx_inline ngx_queue_t *
ngx_http_lua_shdict_get_list_head(ngx_http_lua_shdict_node_t *sd, size_t len)
{
    return (ngx_queue_t *) ngx_align_ptr(((u_char *) &sd->data + len),
                                         NGX_ALIGNMENT);
}

static ngx_inline void
ngx_http_lua_shdict_free_list(ngx_http_lua_shdict_ctx_t *ctx,
                              ngx_http_lua_shdict_node_t *sd)
{
    ngx_queue_t *queue, *q;
    u_char      *p;

    queue = ngx_http_lua_shdict_get_list_head(sd, sd->key_len);

    for (q = ngx_queue_head(queue);
         q != ngx_queue_sentinel(queue);
         q = ngx_queue_next(q))
    {
        p = (u_char *) ngx_queue_data(q,
                                      ngx_http_lua_shdict_list_node_t,
                                      queue);

        ngx_slab_free_locked(ctx->shpool, p);
    }
}


static ngx_inline ngx_http_lua_shdict_zset_t *
ngx_http_lua_shdict_get_rbtree(ngx_http_lua_shdict_node_t *sd, size_t len)
{
    return (ngx_http_lua_shdict_zset_t *)
        ngx_align_ptr(((u_char *) &sd->data + len), NGX_ALIGNMENT);
}

static ngx_inline void
ngx_http_lua_shdict_push_znode_value(lua_State *L,
                                     ngx_http_lua_shdict_zset_node_t *zset_node)
{
    double num;
    u_char c;

    if (zset_node->value.data) {

        switch (zset_node->value_type) {

        case SHDICT_TSTRING:

            lua_pushlstring(L, (char *) zset_node->value.data,
                            zset_node->value.len);
            break;

        case SHDICT_TNUMBER:

            ngx_memcpy(&num, zset_node->value.data, sizeof(double));

            lua_pushnumber(L, num);
            break;

        case SHDICT_TBOOLEAN:

            c = *zset_node->value.data;

            lua_pushboolean(L, c ? 1 : 0);
            break;

        }
    } else {

        lua_pushlightuserdata(L, NULL);
    }
}


void
ngx_http_lua_shdict_zset_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t               **p;
    ngx_http_lua_shdict_zset_node_t  *sdn, *sdnt;

    for ( ;; ) {

        sdn = (ngx_http_lua_shdict_zset_node_t *) &node->color;
        sdnt = (ngx_http_lua_shdict_zset_node_t *) &temp->color;

        p = ngx_strcmp(sdn->data, sdnt->data) < 0 ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_inline void
ngx_http_lua_shdict_free_rbtree(ngx_http_lua_shdict_ctx_t *ctx,
                                ngx_http_lua_shdict_node_t *sd)
{
    ngx_rbtree_node_t               *node;
    ngx_rbtree_node_t               *tmp;
    ngx_rbtree_node_t               *sentinel;
    ngx_http_lua_shdict_zset_t      *zset;
    ngx_http_lua_shdict_zset_node_t *zset_node;

    zset = ngx_http_lua_shdict_get_rbtree(sd, sd->key_len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    if (node != sentinel) {

        for (node = ngx_rbtree_min(node, sentinel);
             node;
             ngx_slab_free_locked(ctx->shpool, tmp))
        {
            zset_node = (ngx_http_lua_shdict_zset_node_t *) &node->color;

            if (zset_node->value.data) {
                ngx_slab_free_locked(ctx->shpool, zset_node->value.data);
            }

            tmp = node;

            node = ngx_rbtree_next(&zset->rbtree, node);
        }
    }
}


ngx_int_t
ngx_http_lua_shdict_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_lua_shdict_ctx_t  *octx = data;

    size_t                      len;
    ngx_http_lua_shdict_ctx_t  *ctx;

    dd("init zone");

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_lua_shdict_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_lua_shdict_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->lru_queue);

    len = sizeof(" in lua_shared_dict zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in lua_shared_dict zone \"%V\"%Z",
                &shm_zone->shm.name);

#if defined(nginx_version) && nginx_version >= 1005013
    ctx->shpool->log_nomem = 0;
#endif

    return NGX_OK;
}


void
ngx_http_lua_shdict_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_http_lua_shdict_node_t   *sdn, *sdnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sdn = (ngx_http_lua_shdict_node_t *) &node->color;
            sdnt = (ngx_http_lua_shdict_node_t *) &temp->color;

            p = ngx_memn2cmp(sdn->data, sdnt->data, sdn->key_len,
                             sdnt->key_len) < 0 ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_lua_shdict_lookup(ngx_shm_zone_t *shm_zone, ngx_uint_t hash,
    u_char *kdata, size_t klen, ngx_http_lua_shdict_node_t **sdp)
{
    ngx_int_t                    rc;
    ngx_time_t                  *tp;
    uint64_t                     now;
    int64_t                      ms;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    ctx = shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sd = (ngx_http_lua_shdict_node_t *) &node->color;

        rc = ngx_memn2cmp(kdata, sd->data, klen, (size_t) sd->key_len);

        if (rc == 0) {
            ngx_queue_remove(&sd->queue);
            ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

            *sdp = sd;

            dd("node expires: %lld", (long long) sd->expires);

            if (sd->expires != 0) {
                tp = ngx_timeofday();

                now = (uint64_t) tp->sec * 1000 + tp->msec;
                ms = sd->expires - now;

                dd("time to live: %lld", (long long) ms);

                if (ms < 0) {
                    dd("node already expired");
                    return NGX_DONE;
                }
            }

            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *sdp = NULL;

    return NGX_DECLINED;
}


static int
ngx_http_lua_shdict_expire(ngx_http_lua_shdict_ctx_t *ctx, ngx_uint_t n)
{
    ngx_time_t                      *tp;
    uint64_t                         now;
    ngx_queue_t                     *q;
    int64_t                          ms;
    ngx_rbtree_node_t               *node;
    ngx_http_lua_shdict_node_t      *sd;
    int                              freed = 0;

    tp = ngx_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    /*
     * n == 1 deletes one or two expired entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

    while (n < 3) {

        if (ngx_queue_empty(&ctx->sh->lru_queue)) {
            return freed;
        }

        q = ngx_queue_last(&ctx->sh->lru_queue);

        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);

        if (n++ != 0) {

            if (sd->expires == 0) {
                return freed;
            }

            ms = sd->expires - now;
            if (ms > 0) {
                return freed;
            }
        }

        if (sd->value_type == SHDICT_TLIST) {
              ngx_http_lua_shdict_free_list(ctx, sd);
        }

        if (sd->value_type == SHDICT_TZSET) {
            ngx_http_lua_shdict_free_rbtree(ctx, sd);
        }

        ngx_queue_remove(q);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);

        freed++;
    }

    return freed;
}


void
ngx_http_lua_inject_shdict_api(ngx_http_lua_main_conf_t *lmcf, lua_State *L)
{
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_uint_t                   i;
    ngx_shm_zone_t             **zone;

    if (lmcf->shdict_zones != NULL) {
        lua_createtable(L, 0, lmcf->shdict_zones->nelts /* nrec */);
                /* ngx.shared */

#    if nginx_version >= 1011007
        lua_createtable(L, 0 /* narr */, 29 /* nrec */); /* shared mt */
#    else
        lua_createtable(L, 0 /* narr */, 28 /* nrec */); /* shared mt */
#    endif

        lua_pushcfunction(L, ngx_http_lua_shdict_get);
        lua_setfield(L, -2, "get");

        lua_pushcfunction(L, ngx_http_lua_shdict_get_stale);
        lua_setfield(L, -2, "get_stale");

        lua_pushcfunction(L, ngx_http_lua_shdict_set);
        lua_setfield(L, -2, "set");

        lua_pushcfunction(L, ngx_http_lua_shdict_safe_set);
        lua_setfield(L, -2, "safe_set");

        lua_pushcfunction(L, ngx_http_lua_shdict_add);
        lua_setfield(L, -2, "add");

        lua_pushcfunction(L, ngx_http_lua_shdict_safe_add);
        lua_setfield(L, -2, "safe_add");

        lua_pushcfunction(L, ngx_http_lua_shdict_replace);
        lua_setfield(L, -2, "replace");

        lua_pushcfunction(L, ngx_http_lua_shdict_incr);
        lua_setfield(L, -2, "incr");

        lua_pushcfunction(L, ngx_http_lua_shdict_delete);
        lua_setfield(L, -2, "delete");

        lua_pushcfunction(L, ngx_http_lua_shdict_lpush);
        lua_setfield(L, -2, "lpush");

        lua_pushcfunction(L, ngx_http_lua_shdict_rpush);
        lua_setfield(L, -2, "rpush");

        lua_pushcfunction(L, ngx_http_lua_shdict_lpop);
        lua_setfield(L, -2, "lpop");

        lua_pushcfunction(L, ngx_http_lua_shdict_rpop);
        lua_setfield(L, -2, "rpop");

        lua_pushcfunction(L, ngx_http_lua_shdict_llen);
        lua_setfield(L, -2, "llen");

        lua_pushcfunction(L, ngx_http_lua_shdict_zset);
        lua_setfield(L, -2, "zset");

        lua_pushcfunction(L, ngx_http_lua_shdict_zrem);
        lua_setfield(L, -2, "zrem");

        lua_pushcfunction(L, ngx_http_lua_shdict_zget);
        lua_setfield(L, -2, "zget");

        lua_pushcfunction(L, ngx_http_lua_shdict_zgetall);
        lua_setfield(L, -2, "zgetall");

        lua_pushcfunction(L, ngx_http_lua_shdict_zcard);
        lua_setfield(L, -2, "zcard");

        lua_pushcfunction(L, ngx_http_lua_shdict_zscan);
        lua_setfield(L, -2, "zscan");

        lua_pushcfunction(L, ngx_http_lua_shdict_flush_all);
        lua_setfield(L, -2, "flush_all");

        lua_pushcfunction(L, ngx_http_lua_shdict_flush_expired);
        lua_setfield(L, -2, "flush_expired");

        lua_pushcfunction(L, ngx_http_lua_shdict_get_keys);
        lua_setfield(L, -2, "get_keys");

        lua_pushcfunction(L, ngx_http_lua_shdict_fun);
        lua_setfield(L, -2, "fun");

        lua_pushcfunction(L, ngx_http_lua_shared_dict_ttl);
        lua_setfield(L, -2, "ttl");

        lua_pushcfunction(L, ngx_http_lua_shared_dict_expire);
        lua_setfield(L, -2, "expire");

        lua_pushcfunction(L, ngx_http_lua_shared_dict_capacity);
        lua_setfield(L, -2, "capacity");

#    if nginx_version >= 1011007
        lua_pushcfunction(L, ngx_http_lua_shared_dict_free_space);
        lua_setfield(L, -2, "free_space");
#    endif

        lua_pushvalue(L, -1); /* shared mt mt */
        lua_setfield(L, -2, "__index"); /* shared mt */

        zone = lmcf->shdict_zones->elts;

        for (i = 0; i < lmcf->shdict_zones->nelts; i++) {
            ctx = zone[i]->data;

            lua_pushlstring(L, (char *) ctx->name.data, ctx->name.len);
                /* shared mt key */

            lua_createtable(L, 1 /* narr */, 0 /* nrec */);
                /* table of zone[i] */
            lua_pushlightuserdata(L, zone[i]); /* shared mt key ud */
            lua_rawseti(L, -2, SHDICT_USERDATA_INDEX); /* {zone[i]} */
            lua_pushvalue(L, -3); /* shared mt key ud mt */
            lua_setmetatable(L, -2); /* shared mt key ud */
            lua_rawset(L, -4); /* shared mt */
        }

        lua_pop(L, 1); /* shared */

    } else {
        lua_newtable(L);    /* ngx.shared */
    }

    lua_setfield(L, -2, "shared");
}


static int
ngx_http_lua_shdict_get(lua_State *L)
{
    return ngx_http_lua_shdict_get_helper(L, 0 /* stale */);
}


static int
ngx_http_lua_shdict_get_stale(lua_State *L)
{
    return ngx_http_lua_shdict_get_helper(L, 1 /* stale */);
}


static ngx_inline ngx_shm_zone_t *
ngx_http_lua_shdict_get_zone(lua_State *L, int index)
{
    ngx_shm_zone_t      *zone;

    lua_rawgeti(L, index, SHDICT_USERDATA_INDEX);
    zone = lua_touserdata(L, -1);
    lua_pop(L, 1);

    return zone;
}


static u_char *
ngx_http_lua_get_string(lua_State *L, int index, size_t *len)
{
    if (lua_touserdata(L, index) == NULL) {
        return (u_char *) luaL_checklstring(L, index, len);
    }

    if (!luaL_callmeta(L, index, "__tostring")) {
        luaL_error(L, "userdata at #%d doesn't have tostring method", index);
        return NULL;
    }

    return (u_char *) lua_tolstring(L, -1, len);
}


typedef struct {
    u_char err[NGX_MAX_ERROR_STR];
    ngx_http_lua_value_t value;
    uint32_t user_flags;
    int stale;
} lua_shdict_get_helper_getter_ctx_t;


static ngx_int_t
ngx_http_lua_shdict_get_helper_getter(ngx_http_lua_value_t value,
    uint32_t user_flags, int stale, void *userdata)
{
    lua_shdict_get_helper_getter_ctx_t *ctx = userdata;
    ctx->value = value;
    ctx->user_flags = user_flags;
    ctx->stale = stale;
    return NGX_OK;
}


static void
ngx_http_lua_shdict_get_helper_err_handler(void *userdata, const char *fmt, ...)
{
    lua_shdict_get_helper_getter_ctx_t *ctx = userdata;
    va_list args;
    va_start(args, fmt);
    ngx_snprintf(ctx->err, NGX_MAX_ERROR_STR, fmt, args);
    va_end(args);
}


static int
ngx_http_lua_shdict_get_helper(lua_State *L, int get_stale)
{
    int                                n;
    ngx_str_t                          name;
    ngx_str_t                          key;
    ngx_int_t                          rc;
    ngx_http_lua_shdict_ctx_t         *ctx;
    ngx_shm_zone_t                    *zone;
    lua_shdict_get_helper_getter_ctx_t u;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting exactly two arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    u.err[0] = 0;

    ctx = zone->data;
    name = ctx->name;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%V\" in shared dict \"%V\"", &key, &name);
#endif /* NGX_DEBUG */

    rc = ngx_http_lua_shdict_api_fun_impl(zone, key,
        ngx_http_lua_shdict_get_helper_getter,
        ngx_http_lua_shdict_get_helper_err_handler,
        get_stale, &u);

    if (rc == NGX_OK) {

        switch (u.value.type) {

        case SHDICT_TSTRING:

            lua_pushlstring(L, (char *) u.value.value.s.data, u.value.value.s.len);
            break;

        case SHDICT_TNUMBER:

            lua_pushnumber(L, u.value.value.n);
            break;

        case SHDICT_TBOOLEAN:

            lua_pushboolean(L, u.value.value.b);
            break;

        case SHDICT_TLIST:

            lua_pushnil(L);
            lua_pushliteral(L, "value is a list");
            return 2;

        case SHDICT_TZSET:

            lua_pushnil(L);
            lua_pushliteral(L, "value is a zset");
            return 2;

        case SHDICT_TUSERDATA:

            lua_pushnil(L);
            lua_pushliteral(L, "value is a native userdata");
            return 2;

        default:

            return luaL_error(L, "bad value type found for key %s in "
                              "shared_dict %s: %d", key.data, name.data,
                              u.value.type);
        }

        if (get_stale) {

            /* always return value, flags, stale */

            if (u.user_flags) {
                lua_pushinteger(L, (lua_Integer) u.user_flags);

            } else {
                lua_pushnil(L);
            }

            lua_pushboolean(L, u.stale);
            return 3;
        }

        if (u.user_flags) {
            lua_pushinteger(L, (lua_Integer) u.user_flags);
            return 2;
        }
    } else {

        if (rc == NGX_ERROR) {

            return luaL_error(L, u.err[0] ? (const char *) u.err : "unknown error");
        }

        /* not found */

        lua_pushnil(L);
    }

    return 1;
}


static int
ngx_http_lua_shdict_delete(lua_State *L)
{
    int             n;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    lua_pushnil(L);

    return ngx_http_lua_shdict_lua_set_helper(L, 0);
}


static int
ngx_http_lua_shdict_flush_all(lua_State *L)
{
    ngx_queue_t                 *q;
    ngx_http_lua_shdict_node_t  *sd;
    int                          n;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_shm_zone_t              *zone;

    n = lua_gettop(L);

    if (n != 1) {
        return luaL_error(L, "expecting 1 argument, but seen %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the ngx_shm_zone_t pointer");
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    for (q = ngx_queue_head(&ctx->sh->lru_queue);
         q != ngx_queue_sentinel(&ctx->sh->lru_queue);
         q = ngx_queue_next(q))
    {
        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);
        sd->expires = 1;
    }

    ngx_http_lua_shdict_expire(ctx, 0);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 0;
}


static int
ngx_http_lua_shdict_flush_expired(lua_State *L)
{
    ngx_queue_t                     *q, *prev;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_shm_zone_t                  *zone;
    ngx_time_t                      *tp;
    int                              freed = 0;
    int                              attempts = 0;
    ngx_rbtree_node_t               *node;
    uint64_t                         now;
    int                              n;

    n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 argument(s), but saw %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the ngx_shm_zone_t pointer");
    }

    if (n == 2) {
        attempts = luaL_checkint(L, 2);
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (ngx_queue_empty(&ctx->sh->lru_queue)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnumber(L, 0);
        return 1;
    }

    tp = ngx_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    q = ngx_queue_last(&ctx->sh->lru_queue);

    while (q != ngx_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = ngx_queue_prev(q);

        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);

        if (sd->expires != 0 && sd->expires <= now) {

            if (sd->value_type == SHDICT_TLIST) {
                ngx_http_lua_shdict_free_list(ctx, sd);
            }

            if (sd->value_type == SHDICT_TZSET) {
                ngx_http_lua_shdict_free_rbtree(ctx, sd);
            }

            ngx_queue_remove(q);

            node = (ngx_rbtree_node_t *)
                ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

            ngx_rbtree_delete(&ctx->sh->rbtree, node);
            ngx_slab_free_locked(ctx->shpool, node);
            freed++;

            if (attempts && freed == attempts) {
                break;
            }
        }

        q = prev;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, freed);
    return 1;
}


/*
 * This trades CPU for memory. This is potentially slow. O(2n)
 */

static int
ngx_http_lua_shdict_get_keys(lua_State *L)
{
    ngx_queue_t                 *q, *prev;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_shm_zone_t              *zone;
    ngx_time_t                  *tp;
    int                          total = 0;
    int                          attempts = 1024;
    uint64_t                     now;
    int                          n;

    n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 argument(s), "
                          "but saw %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the ngx_shm_zone_t pointer");
    }

    if (n == 2) {
        attempts = luaL_checkint(L, 2);
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (ngx_queue_empty(&ctx->sh->lru_queue)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_createtable(L, 0, 0);
        return 1;
    }

    tp = ngx_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    /* first run through: get total number of elements we need to allocate */

    q = ngx_queue_last(&ctx->sh->lru_queue);

    while (q != ngx_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = ngx_queue_prev(q);

        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);

        if (sd->expires == 0 || sd->expires > now) {
            total++;
            if (attempts && total == attempts) {
                break;
            }
        }

        q = prev;
    }

    lua_createtable(L, total, 0);

    /* second run through: add keys to table */

    total = 0;
    q = ngx_queue_last(&ctx->sh->lru_queue);

    while (q != ngx_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = ngx_queue_prev(q);

        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);

        if (sd->expires == 0 || sd->expires > now) {
            lua_pushlstring(L, (char *) sd->data, sd->key_len);
            lua_rawseti(L, -2, ++total);
            if (attempts && total == attempts) {
                break;
            }
        }

        q = prev;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    /* table is at top of stack */
    return 1;
}


static int
ngx_http_lua_shdict_set_helper(ngx_shm_zone_t *zone,
    ngx_str_t key,
    ngx_str_t value, int value_type,
    int64_t exptime, int32_t user_flags, int flags, int *forcible)
{
    int                          i, n;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    u_char                      *p;
    ngx_rbtree_node_t           *node;
    ngx_time_t                  *tp;

    ctx = zone->data;

    if (forcible != NULL) {
        *forcible = 0;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (flags & NGX_HTTP_LUA_SHDICT_REPLACE) {

        if (rc == NGX_DECLINED || rc == NGX_DONE) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_LUA_SHDICT_NOT_FOUND;
        }

        /* rc == NGX_OK */

        goto replace;
    }

    if (flags & NGX_HTTP_LUA_SHDICT_ADD) {

        if (rc == NGX_OK) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_LUA_SHDICT_EXISTS;
        }

        if (rc == NGX_DONE) {
            /* exists but expired */

            dd("go to replace");
            goto replace;
        }

        /* rc == NGX_DECLINED */

        dd("go to insert");
        goto insert;
    }

    if (rc == NGX_OK || rc == NGX_DONE) {

        if (value_type == LUA_TNIL) {
            goto remove;
        }

replace:

        if (value.data
            && value.len == (size_t) sd->value_len
            && sd->value_type != SHDICT_TLIST
            && sd->value_type != SHDICT_TZSET)
        {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict set: found old entry and value "
                           "size matched, reusing it");

            ngx_queue_remove(&sd->queue);
            ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

            sd->key_len = (u_short) key.len;

            if (exptime > 0) {
                tp = ngx_timeofday();
                sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                              + (uint64_t) exptime;

            } else {
                sd->expires = 0;
            }

            sd->user_flags = user_flags;

            sd->value_len = (uint32_t) value.len;

            dd("setting value type to %d", value_type);

            sd->value_type = (uint8_t) value_type;

            p = ngx_copy(sd->data, key.data, key.len);
            ngx_memcpy(p, value.data, value.len);

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return NGX_LUA_SHDICT_OK;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict set: found old entry but value size "
                       "NOT matched, removing it first");

remove:

        if (sd->value_type == SHDICT_TLIST) {
            ngx_http_lua_shdict_free_list(ctx, sd);
        }

        if (sd->value_type == SHDICT_TZSET) {
            ngx_http_lua_shdict_free_rbtree(ctx, sd);
        }

        ngx_queue_remove(&sd->queue);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);

    }

insert:

    /* rc == NGX_DECLINED or value size unmatch */

    if (value.data == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_LUA_SHDICT_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict set: creating a new entry");

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key.len
        + value.len;

    dd("overhead = %d", (int) (offsetof(ngx_rbtree_node_t, color)
       + offsetof(ngx_http_lua_shdict_node_t, data)));

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {

        if (flags & NGX_HTTP_LUA_SHDICT_SAFE_STORE) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_LUA_SHDICT_NO_MEMORY;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict set: overriding non-expired items "
                       "due to memory shortage for entry \"%V\"", &key);

        for (i = 0; i < 30; i++) {
            if (ngx_http_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }

            if (forcible != NULL) {
                *forcible = 1;
            }

            node = ngx_slab_alloc_locked(ctx->shpool, n);
            if (node != NULL) {
                goto allocated;
            }
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_LUA_SHDICT_NO_MEMORY;
    }

allocated:

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    node->key = hash;
    sd->key_len = (u_short) key.len;

    if (exptime > 0) {
        tp = ngx_timeofday();
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) exptime;

    } else {
        sd->expires = 0;
    }

    sd->user_flags = user_flags;

    sd->value_len = (uint32_t) value.len;

    dd("setting value type to %d", value_type);

    sd->value_type = (uint8_t) value_type;

    p = ngx_copy(sd->data, key.data, key.len);
    ngx_memcpy(p, value.data, value.len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_LUA_SHDICT_OK;
}


static ngx_int_t
ngx_http_lua_shdict_api_set_impl(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags, int flags)
{
    ngx_str_t val;
    u_char    c;

    switch (value.type) {

    case SHDICT_TSTRING:
    case SHDICT_TUSERDATA:

        val = value.value.s;
        break;

    case SHDICT_TNUMBER:

        val.len = sizeof(double);
        val.data = (u_char *) &value.value.n;
        break;

    case SHDICT_TBOOLEAN:

        c = (u_char) value.value.b;
        val.len = sizeof(u_char);
        val.data = &c;
        break;

    default:

        return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
    }

    return ngx_http_lua_shdict_set_helper(shm_zone, key, val, value.type,
            (int64_t) (exptime * 1000), user_flags, flags, NULL);
}


ngx_int_t
ngx_http_lua_shdict_api_get(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t *value)
{
    return ngx_http_lua_shared_dict_get(shm_zone, key.data, key.len, value);
}


static ngx_int_t
ngx_http_lua_shdict_api_fun_impl(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, get_fun_t fun, err_fun_t errlog, int get_stale,
    void *userdata)
{
    u_char                      *data;
    size_t                       len;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_http_lua_value_t         value;

    if (shm_zone == NULL) {
        return NGX_LUA_SHDICT_ERROR;
    }

    if (errlog == NULL) {
        return NGX_LUA_SHDICT_ERROR;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    if (!get_stale) {
        ngx_http_lua_shdict_expire(ctx, 1);
    }
#endif

    rc = ngx_http_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || (rc == NGX_DONE && !get_stale)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return rc;
    }

    /* rc == NGX_OK */

    value.type = sd->value_type;

    dd("type: %d", (int) value.type);

    data = sd->data + sd->key_len;
    len = (size_t) sd->value_len;

    switch (value.type) {

    case SHDICT_TSTRING:
    case SHDICT_TUSERDATA:

        value.value.s.data = data;
        value.value.s.len = len;
        break;

    case SHDICT_TNUMBER:

        if (len != sizeof(double)) {
            errlog(userdata, "bad lua number "
                   "value size found for key %*s: %lu", key.len,
                   key.data, (unsigned long) len);

            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_LUA_SHDICT_ERROR;
        }

        ngx_memcpy(&value.value.n, data, len);
        break;

    case SHDICT_TBOOLEAN:

        if (len != sizeof(u_char)) {
            errlog(userdata, "bad lua boolean "
                   "value size found for key %*s: %lu", key.len,
                   key.data, (unsigned long) len);

            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_LUA_SHDICT_ERROR;
        }

        value.value.b = *data;
        break;

    case SHDICT_TLIST:
    case SHDICT_TZSET:
        break;

    default:
        errlog(userdata, "bad lua value type "
               "found for key %*s: %d", key.len, key.data,
               (int) value.type);

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_LUA_SHDICT_ERROR;
    }

    fun(value, sd->user_flags, rc == NGX_DONE, userdata);

    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return NGX_LUA_SHDICT_OK;
}


static void
ngx_http_lua_shdict_api_errlog(void *userdata, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, fmt, args);
    va_end(args);
}


ngx_int_t
ngx_http_lua_shdict_api_fun(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, get_fun_t fun, void *userdata)
{
    return ngx_http_lua_shdict_api_fun_impl(shm_zone, key, fun,
            ngx_http_lua_shdict_api_errlog, 0, userdata);
}


ngx_int_t
ngx_http_lua_shdict_api_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags)
{
    return ngx_http_lua_shdict_api_set_impl(shm_zone, key, value, exptime,
        user_flags, 0);
}


ngx_int_t
ngx_http_lua_shdict_api_safe_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags)
{
    return ngx_http_lua_shdict_api_set_impl(shm_zone, key, value, exptime,
        user_flags, NGX_HTTP_LUA_SHDICT_SAFE_STORE);
}


ngx_int_t
ngx_http_lua_shdict_api_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags)
{
    return ngx_http_lua_shdict_api_set_impl(shm_zone, key, value, exptime,
        user_flags, NGX_HTTP_LUA_SHDICT_ADD);
}


ngx_int_t
ngx_http_lua_shdict_api_safe_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags)
{
    return ngx_http_lua_shdict_api_set_impl(shm_zone, key, value, exptime,
        user_flags, NGX_HTTP_LUA_SHDICT_ADD|NGX_HTTP_LUA_SHDICT_SAFE_STORE);
}


ngx_int_t
ngx_http_lua_shdict_api_replace(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_lua_value_t value, int exptime,
    int32_t user_flags)
{
    return ngx_http_lua_shdict_api_set_impl(shm_zone, key, value, exptime,
        user_flags, NGX_HTTP_LUA_SHDICT_REPLACE);
}


ngx_int_t
ngx_http_lua_shdict_api_delete(ngx_shm_zone_t *shm_zone,
    ngx_str_t key)
{
    ngx_str_t value;
    ngx_str_null(&value);
    return ngx_http_lua_shdict_set_helper(shm_zone, key, value, 0, 0, 0, 0, 0);
}


static int
ngx_http_lua_shdict_add(lua_State *L)
{
    return ngx_http_lua_shdict_lua_set_helper(L, NGX_HTTP_LUA_SHDICT_ADD);
}


static int
ngx_http_lua_shdict_safe_add(lua_State *L)
{
    return ngx_http_lua_shdict_lua_set_helper(L, NGX_HTTP_LUA_SHDICT_ADD
                                              |NGX_HTTP_LUA_SHDICT_SAFE_STORE);
}


static int
ngx_http_lua_shdict_replace(lua_State *L)
{
    return ngx_http_lua_shdict_lua_set_helper(L, NGX_HTTP_LUA_SHDICT_REPLACE);
}


static int
ngx_http_lua_shdict_set(lua_State *L)
{
    return ngx_http_lua_shdict_lua_set_helper(L, 0);
}


static int
ngx_http_lua_shdict_safe_set(lua_State *L)
{
    return ngx_http_lua_shdict_lua_set_helper(L, NGX_HTTP_LUA_SHDICT_SAFE_STORE);
}


static int
ngx_http_lua_shdict_lua_set_helper(lua_State *L, int flags)
{
    int                          n;
    ngx_str_t                    key;
    ngx_int_t                    rc;
    ngx_str_t                    value;
    int                          value_type;
    double                       num;
    u_char                       c;
    lua_Number                   exptime = 0;
    ngx_shm_zone_t              *zone;
    int32_t                      user_flags = 0;
    int                          forcible = 0;

    n = lua_gettop(L);

    if (n != 3 && n != 4 && n != 5) {
        return luaL_error(L, "expecting 3, 4 or 5 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    value_type = lua_type(L, 3);

    switch (value_type) {

    case SHDICT_TSTRING:
        value.data = (u_char *) lua_tolstring(L, 3, &value.len);
        break;

    case SHDICT_TNUMBER:
        value.len = sizeof(double);
        num = lua_tonumber(L, 3);
        value.data = (u_char *) &num;
        break;

    case SHDICT_TBOOLEAN:
        value.len = sizeof(u_char);
        c = lua_toboolean(L, 3) ? 1 : 0;
        value.data = &c;
        break;

    case LUA_TNIL:
        if (flags & (NGX_HTTP_LUA_SHDICT_ADD|NGX_HTTP_LUA_SHDICT_REPLACE)) {
            lua_pushnil(L);
            lua_pushliteral(L, "attempt to add or replace nil values");
            return 2;
        }

        ngx_str_null(&value);
        break;

    case SHDICT_TUSERDATA:
        value.data = (u_char *) ngx_http_lua_get_string(L, 3, &value.len);
        value_type = SHDICT_TSTRING;
        break;


    default:
        lua_pushnil(L);
        lua_pushliteral(L, "bad value type");
        return 2;
    }

    if (n >= 4 && !lua_isnil(L, 4)) {
        exptime = luaL_checknumber(L, 4);
        if (exptime < 0) {
            return luaL_error(L, "bad \"exptime\" argument");
        }
    }

    if (n == 5 && !lua_isnil(L, 5)) {
        user_flags = (uint32_t) luaL_checkinteger(L, 5);
    }

    rc = ngx_http_lua_shdict_set_helper(zone, key, value, value_type,
        (int64_t) (exptime * 1000), user_flags, flags, &forcible);

    switch (rc) {
    case NGX_LUA_SHDICT_OK:
        break;

    case NGX_LUA_SHDICT_NOT_FOUND:
        lua_pushboolean(L, 0);
        lua_pushliteral(L, "not found");
        lua_pushboolean(L, 0);
        return 3;

    case NGX_LUA_SHDICT_EXISTS:
        lua_pushboolean(L, 0);
        lua_pushliteral(L, "exists");
        lua_pushboolean(L, 0);
        return 3;

    case NGX_LUA_SHDICT_NO_MEMORY:
        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        lua_pushboolean(L, forcible);
        return 3;

    default:
        break;
        /* not reachable */
    }

    lua_pushboolean(L, 1);
    lua_pushnil(L);
    lua_pushboolean(L, forcible);
    return 3;
}


static int
ngx_http_lua_shdict_incr(lua_State *L)
{
    int                          i, n;
    ngx_str_t                    key;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    double                       num;
    double                       init = 0;
    u_char                      *p;
    ngx_shm_zone_t              *zone;
    double                       value;
    ngx_rbtree_node_t           *node;
                         /* indicates whether to foricibly override other
                          * valid entries */
    int                          forcible = 0;

    n = lua_gettop(L);

    if (n != 3 && n != 4) {
        return luaL_error(L, "expecting 3 or 4 arguments, but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the ngx_shm_zone_t pointer");
    }

    ctx = zone->data;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    value = luaL_checknumber(L, 3);

    if (n == 4 && !lua_isnil(L, 4)) {
        init = luaL_checknumber(L, 4);
    }

    dd("looking up key %.*s in shared dict %.*s", (int) key.len, key.data,
       (int) ctx->name.len, ctx->name.data);

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {

        if (n == 3) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushnil(L);
            lua_pushliteral(L, "not found");
            return 2;
        }

        /* add value */
        num = value + init;

        if (rc == NGX_DONE) {

            /* found an expired item */

            if ((size_t) sd->value_len == sizeof(double)
                && sd->value_type != SHDICT_TLIST
                && sd->value_type != SHDICT_TZSET)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                               "lua shared dict incr: found old entry and "
                               "value size matched, reusing it");

                ngx_queue_remove(&sd->queue);
                ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

                dd("go to setvalue");
                goto setvalue;
            }

            dd("go to remove");
            goto remove;
        }

        dd("go to insert");
        goto insert;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TNUMBER || sd->value_len != sizeof(double)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "not a number");
        return 2;
    }

    ngx_queue_remove(&sd->queue);
    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

    dd("setting value type to %d", (int) sd->value_type);

    p = sd->data + key.len;

    ngx_memcpy(&num, p, sizeof(double));
    num += value;

    ngx_memcpy(p, (double *) &num, sizeof(double));

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, num);
    lua_pushnil(L);
    return 2;

remove:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict incr: found old entry but value size "
                   "NOT matched, removing it first");

    if (sd->value_type == SHDICT_TLIST) {
        ngx_http_lua_shdict_free_list(ctx, sd);
    }

    if (sd->value_type == SHDICT_TZSET) {
        ngx_http_lua_shdict_free_rbtree(ctx, sd);
    }

    ngx_queue_remove(&sd->queue);

    node = (ngx_rbtree_node_t *)
               ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

    ngx_rbtree_delete(&ctx->sh->rbtree, node);

    ngx_slab_free_locked(ctx->shpool, node);

insert:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict incr: creating a new entry");

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key.len
        + sizeof(double);

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict incr: overriding non-expired items "
                       "due to memory shortage for entry \"%V\"", &key);

        for (i = 0; i < 30; i++) {
            if (ngx_http_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }

            forcible = 1;

            node = ngx_slab_alloc_locked(ctx->shpool, n);
            if (node != NULL) {
                goto allocated;
            }
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        lua_pushboolean(L, forcible);
        return 3;
    }

allocated:

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    node->key = hash;

    sd->key_len = (u_short) key.len;

    sd->value_len = (uint32_t) sizeof(double);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

setvalue:

    sd->user_flags = 0;

    sd->expires = 0;

    dd("setting value type to %d", LUA_TNUMBER);

    sd->value_type = (uint8_t) LUA_TNUMBER;

    p = ngx_copy(sd->data, key.data, key.len);
    ngx_memcpy(p, (double *) &num, sizeof(double));

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, num);
    lua_pushnil(L);
    lua_pushboolean(L, forcible);
    return 3;
}


typedef struct {
  ngx_http_lua_value_t *value;
  ngx_str_t key;
} ngx_http_lua_shared_dict_get_getter_ctx_t;


static ngx_int_t
ngx_http_lua_shared_dict_get_getter(ngx_http_lua_value_t dict_value,
    uint32_t user_flags, int stale, void *userdata)
{
    ngx_http_lua_shared_dict_get_getter_ctx_t *ctx = userdata;
    ngx_http_lua_value_t                      *value = ctx->value;
    size_t                                     len;

    switch (dict_value.type) {
    case SHDICT_TSTRING:

        if (value->value.s.data == NULL || value->value.s.len == 0) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no string buffer "
                          "initialized");
            return NGX_ERROR;
        }

        len = dict_value.value.s.len;

        if (len > value->value.s.len) {
            len = value->value.s.len;

        } else {
            value->value.s.len = len;
        }

        ngx_memcpy(value->value.s.data, dict_value.value.s.data, len);
        break;

    case SHDICT_TNUMBER:

        value->value.n = dict_value.value.n;
        break;

    case SHDICT_TBOOLEAN:

        value->value.b = dict_value.value.b;
        break;

    default:

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bad lua value type "
                      "found for key %*s: %d", ctx->key.len, ctx->key.data,
                      (int) dict_value.type);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_lua_shared_dict_get(ngx_shm_zone_t *zone, u_char *key_data,
    size_t key_len, ngx_http_lua_value_t *value)
{
    ngx_http_lua_shared_dict_get_getter_ctx_t ctx;

    ctx.key.data = key_data;
    ctx.key.len = key_len;

    return ngx_http_lua_shdict_api_fun(zone, ctx.key,
        ngx_http_lua_shared_dict_get_getter, &ctx);
}


static int
ngx_http_lua_shdict_lpush(lua_State *L)
{
    return ngx_http_lua_shdict_push_helper(L, NGX_HTTP_LUA_SHDICT_LEFT);
}


static int
ngx_http_lua_shdict_rpush(lua_State *L)
{
    return ngx_http_lua_shdict_push_helper(L, NGX_HTTP_LUA_SHDICT_RIGHT);
}


static int
ngx_http_lua_shdict_push_helper(lua_State *L, int flags)
{
    int                              n;
    ngx_str_t                        key;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_str_t                        value;
    int                              value_type;
    double                           num;
    ngx_rbtree_node_t               *node;
    ngx_shm_zone_t                  *zone;
    ngx_http_lua_shdict_list_node_t *lnode;
    ngx_queue_t                     *queue;

    n = lua_gettop(L);

    if (n != 3) {
        return luaL_error(L, "expecting 3 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    value_type = lua_type(L, 3);

    switch (value_type) {

    case SHDICT_TSTRING:
        value.data = (u_char *) lua_tolstring(L, 3, &value.len);
        break;

    case SHDICT_TNUMBER:
        value.len = sizeof(double);
        num = lua_tonumber(L, 3);
        value.data = (u_char *) &num;
        break;

    case SHDICT_TUSERDATA:
        value.data = (u_char *) ngx_http_lua_get_string(L, 3, &value.len);
        value_type = SHDICT_TSTRING;
        break;

    default:
        lua_pushnil(L);
        lua_pushliteral(L, "bad value type");
        return 2;
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    /* exists but expired */

    if (rc == NGX_DONE) {

        if (sd->value_type != SHDICT_TLIST) {
            /* TODO: reuse when length matched */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict push: found old entry and value "
                           "type not matched, remove it first");

            if (sd->value_type == SHDICT_TZSET) {
                ngx_http_lua_shdict_free_rbtree(ctx, sd);
            }

            ngx_queue_remove(&sd->queue);

            node = (ngx_rbtree_node_t *)
                        ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

            ngx_rbtree_delete(&ctx->sh->rbtree, node);

            ngx_slab_free_locked(ctx->shpool, node);

            dd("go to init_list");
            goto init_list;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict push: found old entry and value "
                       "type matched, reusing it");

        sd->expires = 0;

        /* free list nodes */

        ngx_http_lua_shdict_free_list(ctx, sd);

        queue = ngx_http_lua_shdict_get_list_head(sd, key.len);

        ngx_queue_init(queue);

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to push_node");
        goto push_node;
    }

    /* exists and not expired */

    if (rc == NGX_OK) {

        if (sd->value_type != SHDICT_TLIST) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushnil(L);
            lua_pushliteral(L, "value not a list");
            return 2;
        }

        queue = ngx_http_lua_shdict_get_list_head(sd, key.len);

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to push_node");
        goto push_node;
    }

    /* rc == NGX_DECLINED, not found */

init_list:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict list: creating a new entry");

    /* NOTICE: we assume the begin point aligned in slab, be careful */
    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key.len
        + sizeof(ngx_queue_t);

    dd("length before aligned: %d", n);

    n = (int) (uintptr_t) ngx_align_ptr(n, NGX_ALIGNMENT);

    dd("length after aligned: %d", n);

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    queue = ngx_http_lua_shdict_get_list_head(sd, key.len);

    node->key = hash;
    sd->key_len = (u_short) key.len;

    sd->expires = 0;

    sd->value_len = 0;

    dd("setting value type to %d", (int) SHDICT_TLIST);

    sd->value_type = (uint8_t) SHDICT_TLIST;

    ngx_memcpy(sd->data, key.data, key.len);

    ngx_queue_init(queue);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

push_node:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict list: creating a new list node");

    n = offsetof(ngx_http_lua_shdict_list_node_t, data)
        + value.len;

    dd("list node length: %d", n);

    lnode = ngx_slab_alloc_locked(ctx->shpool, n);

    if (lnode == NULL) {

        if (sd->value_len == 0) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict list: no memory for create"
                           " list node and list empty, remove it");

            ngx_queue_remove(&sd->queue);

            node = (ngx_rbtree_node_t *)
                        ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

            ngx_rbtree_delete(&ctx->sh->rbtree, node);

            ngx_slab_free_locked(ctx->shpool, node);
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    dd("setting list length to %d", sd->value_len + 1);

    sd->value_len = sd->value_len + 1;

    dd("setting list node value length to %d", (int) value.len);

    lnode->value_len = (uint32_t) value.len;

    dd("setting list node value type to %d", value_type);

    lnode->value_type = (uint8_t) value_type;

    ngx_memcpy(lnode->data, value.data, value.len);

    if (flags == NGX_HTTP_LUA_SHDICT_LEFT) {
        ngx_queue_insert_head(queue, &lnode->queue);

    } else {
        ngx_queue_insert_tail(queue, &lnode->queue);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, sd->value_len);
    return 1;
}


static int
ngx_http_lua_shdict_lpop(lua_State *L)
{
    return ngx_http_lua_shdict_pop_helper(L, NGX_HTTP_LUA_SHDICT_LEFT);
}


static int
ngx_http_lua_shdict_rpop(lua_State *L)
{
    return ngx_http_lua_shdict_pop_helper(L, NGX_HTTP_LUA_SHDICT_RIGHT);
}


static int
ngx_http_lua_shdict_pop_helper(lua_State *L, int flags)
{
    int                              n;
    ngx_str_t                        name;
    ngx_str_t                        key;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_str_t                        value;
    int                              value_type;
    double                           num;
    ngx_rbtree_node_t               *node;
    ngx_shm_zone_t                  *zone;
    ngx_queue_t                     *queue;
    ngx_http_lua_shdict_list_node_t *lnode;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
    name = ctx->name;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        return 1;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TLIST) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value not a list");
        return 2;
    }

    if (sd->value_len <= 0) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad lua list length found for key %s "
                          "in shared_dict %s: %lu", key.data, name.data,
                          (unsigned long) sd->value_len);
    }

    queue = ngx_http_lua_shdict_get_list_head(sd, key.len);

    if (flags == NGX_HTTP_LUA_SHDICT_LEFT) {
        queue = ngx_queue_head(queue);

    } else {
        queue = ngx_queue_last(queue);
    }

    lnode = ngx_queue_data(queue, ngx_http_lua_shdict_list_node_t, queue);

    value_type = lnode->value_type;

    dd("data: %p", lnode->data);
    dd("value len: %d", (int) sd->value_len);

    value.data = lnode->data;
    value.len = (size_t) lnode->value_len;

    switch (value_type) {

    case SHDICT_TSTRING:

        lua_pushlstring(L, (char *) value.data, value.len);
        break;

    case SHDICT_TNUMBER:

        if (value.len != sizeof(double)) {

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return luaL_error(L, "bad lua list node number value size found "
                              "for key %s in shared_dict %s: %lu", key.data,
                              name.data, (unsigned long) value.len);
        }

        ngx_memcpy(&num, value.data, sizeof(double));

        lua_pushnumber(L, num);
        break;

    default:

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad list node value type found for key %s in "
                          "shared_dict %s: %d", key.data, name.data,
                          value_type);
    }

    ngx_queue_remove(queue);

    ngx_slab_free_locked(ctx->shpool, lnode);

    if (sd->value_len == 1) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict list: empty node after pop, "
                       "remove it");

        ngx_queue_remove(&sd->queue);

        node = (ngx_rbtree_node_t *)
                    ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);

    } else {
        sd->value_len = sd->value_len - 1;

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


static int
ngx_http_lua_shdict_llen(lua_State *L)
{
    int                          n;
    ngx_str_t                    key;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_shm_zone_t              *zone;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_OK) {

        if (sd->value_type != SHDICT_TLIST) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushnil(L);
            lua_pushliteral(L, "value not a list");
            return 2;
        }

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnumber(L, (lua_Number) sd->value_len);
        return 1;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, 0);
    return 1;
}


static int
ngx_http_lua_shdict_fun(lua_State *L)
{
    int                          n;
    ngx_str_t                    key;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_str_t                    value;
    int                          value_type;
    double                       num;
    u_char                       c;
    lua_Number                   exptime = 0;
    uint64_t                     expires = 0;
    u_char                      *p;
    ngx_rbtree_node_t           *node;
    ngx_time_t                  *tp;
    ngx_shm_zone_t              *zone;
                         /* indicates whether to foricibly override other
                          * valid entries */
    int32_t                      user_flags = 0;
    ngx_queue_t                 *queue, *q;
    u_char                      *err_msg;
    ngx_str_t                    name;

    n = lua_gettop(L);

    if (n != 3 && n != 4) {
        return luaL_error(L, "expecting 3 or 4 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    if (lua_type(L, 3) != LUA_TFUNCTION) {
        return luaL_error(L, "bad \"callback\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
    name = ctx->name;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%V\" in shared dict \"%V\"", &key, &name);
#endif /* NGX_DEBUG */

    lua_pushvalue(L, 3);

    if (n == 4 && !lua_isnil(L, 4)) {
        exptime = luaL_checknumber(L, 4);
        if (exptime < 0) {
            return luaL_error(L, "bad \"exptime\" argument");
        }
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returns %d", (int) rc);

    /* rc == NGX_OK or rc == NGX_DECLINED or rc == NGX_DONE */

    if (rc == NGX_OK) {
        value_type = sd->value_type;

        dd("data: %p", sd->data);
        dd("key len: %d", (int) sd->key_len);

        value.data = sd->data + sd->key_len;
        value.len = (size_t) sd->value_len;

        user_flags = sd->user_flags;
        expires = sd->expires;
    } else {
        value_type = LUA_TNIL;
    }

    switch (value_type) {

    case LUA_TNIL:

        lua_pushnil(L);
        break;

    case SHDICT_TSTRING:

        lua_pushlstring(L, (char *) value.data, value.len);
        break;

    case SHDICT_TNUMBER:

        if (value.len != sizeof(double)) {

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return luaL_error(L, "bad lua number value size found for key %s "
                              "in shared_dict %s: %lu", key.data, name.data,
                              (unsigned long) value.len);
        }

        ngx_memcpy(&num, value.data, sizeof(double));

        lua_pushnumber(L, num);
        break;

    case SHDICT_TBOOLEAN:

        if (value.len != sizeof(u_char)) {

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return luaL_error(L, "bad lua boolean value size found for key %s "
                              "in shared_dict %s: %lu", key.data, name.data,
                              (unsigned long) value.len);
        }

        c = *value.data;

        lua_pushboolean(L, c ? 1 : 0);
        break;

    case SHDICT_TLIST:

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value is a list");
        return 2;

    default:

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad value type found for key %s in "
                          "shared_dict %s: %d", key.data, name.data,
                          value_type);
    }

    lua_pushinteger(L, user_flags);

    if (lua_pcall(L, 2, 2, 0) != 0) {

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        /*  error occurred when calling user code */
        err_msg = (u_char *) lua_tostring(L, -1);

        if (err_msg == NULL) {
            err_msg = (u_char *) "unknown reason";
        }

        return luaL_error(L, "user callback error "
                          "shared_dict %s: %s", name.data, err_msg);
    }

    value_type = lua_type(L, -2);

    switch (value_type) {

    case SHDICT_TSTRING:
        value.data = (u_char *) lua_tolstring(L, -2, &value.len);
        break;

    case SHDICT_TNUMBER:
        value.len = sizeof(double);
        num = lua_tonumber(L, -2);
        value.data = (u_char *) &num;
        break;

    case SHDICT_TBOOLEAN:
        value.len = sizeof(u_char);
        c = lua_toboolean(L, -2) ? 1 : 0;
        value.data = &c;
        break;

    case LUA_TNIL:
        ngx_str_null(&value);
        break;

    default:
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "bad value type");
        return 2;
    }

    if (lua_type(L, -1) != SHDICT_TNUMBER) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "user_flags must be a number "
                          "shared_dict %s", name.data);
    }

    user_flags = (uint32_t) luaL_checkinteger(L, -1);

    if (rc == NGX_OK || rc == NGX_DONE) {

        if (value_type == LUA_TNIL) {
            goto remove;
        }

        if (value.data
            && value.len == (size_t) sd->value_len
            && sd->value_type != SHDICT_TLIST)
        {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict set: found old entry and value "
                           "size matched, reusing it");

            ngx_queue_remove(&sd->queue);
            ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

            sd->key_len = (u_short) key.len;

            if (exptime > 0) {
                tp = ngx_timeofday();
                sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                            + (uint64_t) (exptime * 1000);
            } else {
                sd->expires = expires;
            }

            sd->user_flags = user_flags;

            sd->value_len = (uint32_t) value.len;

            dd("setting value type to %d", value_type);

            sd->value_type = (uint8_t) value_type;

            p = ngx_copy(sd->data, key.data, key.len);
            ngx_memcpy(p, value.data, value.len);

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return 2;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict set: found old entry but value size "
                       "NOT matched, removing it first");

remove:

        if (sd->value_type == SHDICT_TLIST) {
            queue = ngx_http_lua_shdict_get_list_head(sd, key.len);

            for (q = ngx_queue_head(queue);
                 q != ngx_queue_sentinel(queue);
                 q = ngx_queue_next(q))
            {
                p = (u_char *) ngx_queue_data(q,
                                              ngx_http_lua_shdict_list_node_t,
                                              queue);

                ngx_slab_free_locked(ctx->shpool, p);
            }
        }

        ngx_queue_remove(&sd->queue);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);

    }

    /* rc == NGX_DECLINED or value size unmatch */

    if (value.data == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return 2;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict set: creating a new entry");

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key.len
        + value.len;

    dd("overhead = %d", (int) (offsetof(ngx_rbtree_node_t, color)
       + offsetof(ngx_http_lua_shdict_node_t, data)));

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    node->key = hash;
    sd->key_len = (u_short) key.len;

    if (exptime > 0) {
        tp = ngx_timeofday();
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) (exptime * 1000);

    } else {
        sd->expires = expires;
    }

    sd->user_flags = user_flags;

    sd->value_len = (uint32_t) value.len;

    dd("setting value type to %d", value_type);

    sd->value_type = (uint8_t) value_type;

    p = ngx_copy(sd->data, key.data, key.len);
    ngx_memcpy(p, value.data, value.len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 2;
}


static int
ngx_http_lua_shared_dict_capacity(lua_State *L)
{
    int               n;
    ngx_shm_zone_t   *zone;

    n = lua_gettop(L);

    if (n != 1) {
        return luaL_error(L, "expecting only zone argument, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    lua_pushnumber(L, zone->shm.size);

    return 1;
}


#    if nginx_version >= 1011007
static int
ngx_http_lua_shared_dict_free_space(lua_State *L)
{
    int                          n;
    ngx_shm_zone_t              *zone;
    size_t                       bytes;
    ngx_http_lua_shdict_ctx_t   *ctx;

    n = lua_gettop(L);

    if (n != 1) {
        return luaL_error(L, "expecting only zone argument, "
                          "but only seen %d", n);
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);
    bytes = ctx->shpool->pfree * ngx_pagesize;
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, bytes);

    return 1;
}
#    endif /* nginx_version >= 1011007 */


static int
ngx_http_lua_shared_dict_ttl(lua_State *L)
{
    int                          n;
    uint32_t                     hash;
    uint64_t                     now;
    uint64_t                     expires;
    ngx_str_t                    key;
    ngx_int_t                    rc;
    ngx_time_t                  *tp;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_shm_zone_t              *zone;
    ngx_http_lua_shdict_node_t  *sd;
#if (NGX_DEBUG)
    ngx_str_t                    name;
#endif

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
#if (NGX_DEBUG)
    name = ctx->name;
#endif
    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%V\" in shared dict \"%V\"", &key, &name);
#endif /* NGX_DEBUG */

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return rc;
    }

    /* rc == NGX_OK */

    expires = sd->expires;

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (expires == 0) {
      lua_pushnumber(L, 0);

      return 1;
    }

    tp = ngx_timeofday();
    now = (uint64_t) tp->sec * 1000 + tp->msec;

    lua_pushnumber(L, ((double)(expires - now)) / 1000);

    return 1;
}


static int
ngx_http_lua_shared_dict_expire(lua_State *L)
{
    int                          n;
    uint32_t                     hash;
    ngx_str_t                    key;
    ngx_int_t                    rc;
    ngx_time_t                  *tp;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_shm_zone_t              *zone;
    ngx_http_lua_shdict_node_t  *sd;
    double                       exptime;
#if (NGX_DEBUG)
    ngx_str_t                    name;
#endif

    n = lua_gettop(L);

    if (n != 3) {
        return luaL_error(L, "expecting 3 arguments, "
                          "but only seen %d", n);
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
#if (NGX_DEBUG)
    name = ctx->name;
#endif

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    if (lua_isnil(L, 3)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil exptime");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    exptime = luaL_checknumber(L, 3);
    if (exptime < 0) {
        return luaL_error(L, "bad \"exptime\" argument");
    }

    hash = ngx_crc32_short(key.data, key.len);

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%V\" in shared dict \"%V\"", &key, &name);
#endif /* NGX_DEBUG */

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return rc;
    }

    /* rc == NGX_OK */

    if (exptime > 0) {
        tp = ngx_timeofday();
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) (exptime * 1000);

    } else {
        sd->expires = 0;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushboolean(L, 1);

    return 1;
}


static int
ngx_http_lua_shdict_zset(lua_State *L)
{
    int                              n;
    ngx_str_t                        key;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    int                              value_type = 0;
    ngx_str_t                        value;
    ngx_str_t                        old_value;
    double                           num;
    u_char                           c;
    ngx_rbtree_node_t               *node = NULL;
    ngx_rbtree_node_t               *znode = NULL;
    ngx_rbtree_node_t               *sentinel;
    ngx_shm_zone_t                  *zone;
    ngx_str_t                        zkey;
    ngx_http_lua_shdict_zset_t      *zset;
    ngx_http_lua_shdict_zset_node_t *zset_node;
    lua_Number                       exptime = 0;
    ngx_time_t                      *tp;
    u_char                           exists = 0;

    n = lua_gettop(L);

    if (n < 3 || n > 5) {
        return luaL_error(L, "expecting 3, 4 or 5 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    zkey.data = (u_char *) ngx_http_lua_get_string(L, 3, &zkey.len);

    if (zkey.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty zkey");
        return 2;
    }

    if (zkey.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "zkey too long");
        return 2;
    }

    value.data = NULL;

    if (n > 3) {
        value_type = lua_type(L, 4);

        switch (value_type) {

        case SHDICT_TSTRING:
            value.data = (u_char *) lua_tolstring(L, 4, &value.len);
            break;

        case SHDICT_TNUMBER:
            value.len = sizeof(double);
            num = lua_tonumber(L, 4);
            value.data = (u_char *) &num;
            break;

        case SHDICT_TBOOLEAN:
            value.len = sizeof(u_char);
            c = lua_toboolean(L, 4) ? 1 : 0;
            value.data = &c;
            break;

        case SHDICT_TUSERDATA:
            value.data = (u_char *) ngx_http_lua_get_string(L, 4, &value.len);
            value_type = SHDICT_TSTRING;
            break;

        case SHDICT_TNIL:
            break;

        default:
            lua_pushnil(L);
            lua_pushliteral(L, "bad value type");
            return 2;
        }

        if (n == 5 && !lua_isnil(L, 5)) {
            exptime = luaL_checknumber(L, 5);
            if (exptime < 0) {
                return luaL_error(L, "bad \"exptime\" argument");
            }
        }
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DONE) {

        /* exists but expired */

        if (sd->value_type != SHDICT_TZSET) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict zset: found old entry and value "
                           "type not matched, remove it first");

            if (sd->value_type == SHDICT_TLIST) {
                ngx_http_lua_shdict_free_list(ctx, sd);
            }

            ngx_queue_remove(&sd->queue);

            node = (ngx_rbtree_node_t *)
                        ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

            ngx_rbtree_delete(&ctx->sh->rbtree, node);

            ngx_slab_free_locked(ctx->shpool, node);

            dd("go to init_zset");
            goto init_zset;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict zset: found old entry and value "
                       "type matched, reusing it");

        /* free rbtree */

        ngx_http_lua_shdict_free_rbtree(ctx, sd);

        zset = ngx_http_lua_shdict_get_rbtree(sd, key.len);

        ngx_rbtree_init(&zset->rbtree, &zset->sentinel,
                        ngx_http_lua_shdict_zset_insert_value);

        if (exptime > 0) {
            tp = ngx_timeofday();
            sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                          + (uint64_t) (exptime * 1000);

        } else {
            sd->expires = 0;
        }

        sd->value_len = 0;

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to add_node");
        goto add_node;
    }

    /* exists and not expired */

    if (rc == NGX_OK) {

        if (sd->value_type != SHDICT_TZSET) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushnil(L);
            lua_pushliteral(L, "value not a zset");
            return 2;
        }

        zset = ngx_http_lua_shdict_get_rbtree(sd, key.len);

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to add_node");
        goto add_node;
    }

    /* rc == NGX_DECLINED, not found */

init_zset:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict zset: creating a new entry");

    /* NOTICE: we assume the begin point aligned in slab, be careful */
    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key.len
        + sizeof(ngx_http_lua_shdict_zset_t);

    dd("length before aligned: %d", n);

    n = (int) (uintptr_t) ngx_align_ptr(n, NGX_ALIGNMENT);

    dd("length after aligned: %d", n);

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    zset = ngx_http_lua_shdict_get_rbtree(sd, key.len);

    node->key = hash;
    sd->key_len = (u_short) key.len;

    if (exptime > 0) {
        tp = ngx_timeofday();
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) (exptime * 1000);

    } else {
        sd->expires = 0;
    }

    sd->value_len = 0;

    dd("setting value type to %d", (int) SHDICT_TZSET);

    sd->value_type = (uint8_t) SHDICT_TZSET;

    ngx_memcpy(sd->data, key.data, key.len);

    ngx_rbtree_init(&zset->rbtree, &zset->sentinel,
                    ngx_http_lua_shdict_zset_insert_value);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

add_node:

    /* search first */

    znode = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    while (znode != sentinel) {

        zset_node = (ngx_http_lua_shdict_zset_node_t *) &znode->color;

        rc = ngx_strcmp(zkey.data, zset_node->data);

        if (rc < 0) {

            znode = znode->left;
            continue;

        } else if (rc > 0) {

            znode = znode->right;
            continue;

        }

        /* found */

        exists = 1;
        break;
    }

    if (exists == 0) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict zset: creating a new zset node");

        /* NOTICE: we assume the begin point aligned in slab, be careful */
        n = offsetof(ngx_rbtree_node_t, color)
            + offsetof(ngx_http_lua_shdict_zset_node_t, data)
            + zkey.len + 1 /* zero terminated string key */;

        dd("length before aligned: %d", n);

        n = (int) (uintptr_t) ngx_align_ptr(n, NGX_ALIGNMENT);

        dd("length after aligned: %d", n);

        znode = ngx_slab_calloc_locked(ctx->shpool, n);

        if (znode == NULL) {

            if (node != NULL && sd->value_len == 0) {

                ngx_rbtree_delete(&ctx->sh->rbtree, node);

                ngx_queue_remove(&sd->queue);

                ngx_slab_free_locked(ctx->shpool, node);
            }

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushboolean(L, 0);
            lua_pushliteral(L, "no memory");
            return 2;
        }
    }

    zset_node = (ngx_http_lua_shdict_zset_node_t *) &znode->color;

    old_value = zset_node->value;

    if (value.data) {

        dd("setting zset node value length to %d", (int) value.len);

        zset_node->value_type = value_type;
        zset_node->value.len = value.len;
        zset_node->value.data = ngx_slab_alloc_locked(ctx->shpool,
            (uintptr_t) ngx_align_ptr(value.len, NGX_ALIGNMENT));

        if (zset_node->value.data == NULL) {

            if (exists == 0) {
                /* not replaced */
                ngx_slab_free_locked(ctx->shpool, znode);
            }

            if (node != NULL && sd->value_len == 0) {

                ngx_rbtree_delete(&ctx->sh->rbtree, node);

                ngx_queue_remove(&sd->queue);

                ngx_slab_free_locked(ctx->shpool, node);
            }

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushboolean(L, 0);
            lua_pushliteral(L, "no memory");
            return 2;
        }

        ngx_memcpy(zset_node->value.data, value.data, value.len);
    } else {

        ngx_str_null(&zset_node->value);
        zset_node->value_type = 0;
    }

    if (old_value.data) {
        ngx_slab_free_locked(ctx->shpool, old_value.data);
    }

    if (exists == 0) {
        dd("setting zset length to %d", sd->value_len + 1);
        sd->value_len = sd->value_len + 1;
    }

    ngx_memcpy(zset_node->data, zkey.data, zkey.len);
    zset_node->data[zkey.len] = 0;

    ngx_rbtree_insert(&zset->rbtree, znode);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, sd->value_len);

    return 1;
}


static int
ngx_http_lua_shdict_zrem(lua_State *L)
{
    int                              n;
    ngx_str_t                        name;
    ngx_str_t                        key;
    ngx_str_t                        zkey;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_rbtree_node_t               *node;
    ngx_rbtree_node_t               *sentinel;
    ngx_shm_zone_t                  *zone;
    ngx_http_lua_shdict_zset_t      *zset;
    ngx_http_lua_shdict_zset_node_t *zset_node;

    n = lua_gettop(L);

    if (n != 3) {
        return luaL_error(L, "expecting 3 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
    name = ctx->name;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    zkey.data = (u_char *) ngx_http_lua_get_string(L, 3, &zkey.len);

    if (zkey.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty zkey");
        return 2;
    }

    if (zkey.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "zkey too long");
        return 2;
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        return 1;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TZSET) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;
    }

    if (sd->value_len <= 0) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad lua zset length found for key %s "
                          "in shared_dict %s: %lu", key.data, name.data,
                          (unsigned long) sd->value_len);
    }

    zset = ngx_http_lua_shdict_get_rbtree(sd, key.len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    while (node != sentinel) {

        zset_node = (ngx_http_lua_shdict_zset_node_t *) &node->color;

        rc = ngx_strcmp(zkey.data, zset_node->data);

        if (rc < 0) {

            node = node->left;
            continue;

        } else if (rc > 0) {

            node = node->right;
            continue;

        }

        /* found */

        ngx_http_lua_shdict_push_znode_value(L, zset_node);

        if (zset_node->value.data) {
            ngx_slab_free_locked(ctx->shpool, zset_node->value.data);
        }

        ngx_rbtree_delete(&zset->rbtree, node);
        ngx_slab_free_locked(ctx->shpool, node);

        sd->value_len = sd->value_len - 1;

        goto ret;
    }

    lua_pushlightuserdata(L, NULL);

ret:

    dd("value len: %d", (int) sd->value_len);

    if (sd->value_len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict zset: empty node after zrem, "
                       "remove it");

        ngx_queue_remove(&sd->queue);

        node = (ngx_rbtree_node_t *)
                    ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);

    } else {
        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


static int
ngx_http_lua_shdict_zcard(lua_State *L)
{
    int                              n;
    ngx_str_t                        name;
    ngx_str_t                        key;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_shm_zone_t                  *zone;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
    name = ctx->name;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        return 1;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TZSET) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;
    }

    if (sd->value_len <= 0) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad lua zgetall length found for key %s "
                          "in shared_dict %s: %lu", key.data, name.data,
                          (unsigned long) sd->value_len);
    }

    lua_pushinteger(L, sd->value_len);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


static int
ngx_http_lua_shdict_zget(lua_State *L)
{
    int                              n;
    ngx_str_t                        name;
    ngx_str_t                        key;
    ngx_str_t                        zkey;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_rbtree_node_t               *node;
    ngx_rbtree_node_t               *sentinel;
    ngx_shm_zone_t                  *zone;
    ngx_http_lua_shdict_zset_t      *zset;
    ngx_http_lua_shdict_zset_node_t *zset_node;

    n = lua_gettop(L);

    if (n != 3) {
        return luaL_error(L, "expecting 3 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
    name = ctx->name;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    zkey.data = (u_char *) ngx_http_lua_get_string(L, 3, &zkey.len);

    if (zkey.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty zkey");
        return 2;
    }

    if (zkey.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "zkey too long");
        return 2;
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        return 1;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TZSET) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;
    }

    if (sd->value_len <= 0) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad lua zget length found for key %s "
                          "in shared_dict %s: %lu", key.data, name.data,
                          (unsigned long) sd->value_len);
    }

    zset = ngx_http_lua_shdict_get_rbtree(sd, key.len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    while (node != sentinel) {

        zset_node = (ngx_http_lua_shdict_zset_node_t *) &node->color;

        rc = ngx_strcmp(zkey.data, zset_node->data);

        if (rc < 0) {

            node = node->left;
            continue;

        } else if (rc > 0) {

            node = node->right;
            continue;

        }

        /* push zkey */
        lua_pushlstring(L, (char *) zkey.data, zkey.len);

        /* push zvalue */
        ngx_http_lua_shdict_push_znode_value(L, zset_node);

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return 2;
    }

    lua_pushnil(L);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


static int
ngx_http_lua_shdict_zgetall(lua_State *L)
{
    int                              n;
    ngx_str_t                        name;
    ngx_str_t                        key;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_rbtree_node_t               *node;
    ngx_rbtree_node_t               *sentinel;
    ngx_shm_zone_t                  *zone;
    ngx_http_lua_shdict_zset_t      *zset;
    ngx_http_lua_shdict_zset_node_t *zset_node;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
    name = ctx->name;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        return 1;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TZSET) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;
    }

    if (sd->value_len <= 0) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad lua zgetall length found for key %s "
                          "in shared_dict %s: %lu", key.data, name.data,
                          (unsigned long) sd->value_len);
    }

    zset = ngx_http_lua_shdict_get_rbtree(sd, key.len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    lua_createtable(L, sd->value_len, 0);

    if (node != sentinel) {
        n = 1;

        for (node = ngx_rbtree_min(node, sentinel);
             node;
             node = ngx_rbtree_next(&zset->rbtree, node))
        {
            zset_node = (ngx_http_lua_shdict_zset_node_t *) &node->color;

            lua_createtable(L, 2, 0);

            /* push zkey */
            lua_pushstring(L, (char *) zset_node->data);
            lua_rawseti(L, -2, 1);

            /* push zvalue */
            ngx_http_lua_shdict_push_znode_value(L, zset_node);
            lua_rawseti(L, -2, 2);

            lua_rawseti(L, -2, n++);
        }
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


static int
ngx_http_lua_shdict_zscan(lua_State *L)
{
    int                              n;
    ngx_str_t                        name;
    ngx_str_t                        key;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_http_lua_shdict_ctx_t       *ctx;
    ngx_http_lua_shdict_node_t      *sd;
    ngx_rbtree_node_t               *node;
    ngx_rbtree_node_t               *tmp = NULL;
    ngx_rbtree_node_t               *sentinel;
    ngx_shm_zone_t                  *zone;
    ngx_http_lua_shdict_zset_t      *zset;
    ngx_http_lua_shdict_zset_node_t *zset_node;
    ngx_str_t                        lbound;
    u_char                          *err_msg;

    n = lua_gettop(L);

    if (n != 3 && n != 4) {
        return luaL_error(L, "expecting 3 or 4 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    if (lua_type(L, 3) != LUA_TFUNCTION) {
        return luaL_error(L, "bad \"callback\" argument");
    }

    ctx = zone->data;
    name = ctx->name;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) ngx_http_lua_get_string(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = ngx_crc32_short(key.data, key.len);

    if (n == 4) {
        lbound.data = (u_char *) lua_tolstring(L, 4, &lbound.len);
    } else {
        lbound.data = NULL;
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        return 1;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TZSET) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;
    }

    if (sd->value_len <= 0) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad lua zgetall length found for key %s "
                          "in shared_dict %s: %lu", key.data, name.data,
                          (unsigned long) sd->value_len);
    }

    zset = ngx_http_lua_shdict_get_rbtree(sd, key.len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    if (node != sentinel) {

        n = lua_gettop(L);

        if (lbound.data != NULL) {

            while (node != sentinel) {

                zset_node = (ngx_http_lua_shdict_zset_node_t *) &node->color;

                rc = ngx_strncmp(lbound.data, zset_node->data, lbound.len);

                if (rc <= 0) {

                    if (rc == 0) {
                        tmp = node;
                    }

                    node = node->left;

                    continue;

                } else if (rc > 0) {

                    node = node->right;
                    continue;

                }
            }

            if (tmp != NULL) {
                node = tmp;
            }
        } else {

            node = ngx_rbtree_min(node, sentinel);
        }

        if (node != sentinel) {

            for (; node; node = ngx_rbtree_next(&zset->rbtree, node))
            {
                lua_pushvalue(L, 3);

                zset_node = (ngx_http_lua_shdict_zset_node_t *) &node->color;

                /* push zkey */
                lua_pushstring(L, (char *) zset_node->data);

                /* push zvalue */
                ngx_http_lua_shdict_push_znode_value(L, zset_node);

                if (lua_pcall(L, 2, 2, 0) != 0) {

                    ngx_shmtx_unlock(&ctx->shpool->mutex);

                    /*  error occurred when calling user code */
                    err_msg = (u_char *) lua_tostring(L, -1);

                    if (err_msg == NULL) {
                        err_msg = (u_char *) "unknown reason";
                    }

                    return luaL_error(L, "user callback error "
                                      "shared_dict %s: %s", name.data, err_msg);
                }

                if (lua_isboolean(L, -1)) {

                    if (lua_toboolean(L, -1)) {

                        /* stop on true */
                        break;
                    }
                }

                lua_settop(L, n);
            }
        }
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushboolean(L, 1);

    return 1;
}


ngx_shm_zone_t *
ngx_http_lua_find_zone(u_char *name_data, size_t name_len)
{
    ngx_str_t                       *name;
    ngx_uint_t                       i;
    ngx_shm_zone_t                  *zone;
    ngx_http_lua_shm_zone_ctx_t     *ctx;
    volatile ngx_list_part_t        *part;

    part = &ngx_cycle->shared_memory.part;
    zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            zone = part->elts;
            i = 0;
        }

        name = &zone[i].shm.name;

        dd("name: [%.*s] %d", (int) name->len, name->data, (int) name->len);
        dd("name2: [%.*s] %d", (int) name_len, name_data, (int) name_len);

        if (name->len == name_len
            && ngx_strncmp(name->data, name_data, name_len) == 0)
        {
            ctx = (ngx_http_lua_shm_zone_ctx_t *) zone[i].data;
            return &ctx->zone;
        }
    }

    return NULL;
}


#ifndef NGX_LUA_NO_FFI_API
int
ngx_http_lua_ffi_shdict_store(ngx_shm_zone_t *zone, int op, u_char *key,
    size_t key_len, int value_type, u_char *str_value_buf,
    size_t str_value_len, double num_value, int exptime, int user_flags,
    char **errmsg, int *forcible)
{
    int                          i, n;
    u_char                       c, *p;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_time_t                  *tp;
    ngx_rbtree_node_t           *node;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    if (zone == NULL) {
        return NGX_ERROR;
    }

    dd("exptime: %d", exptime);

    ctx = zone->data;

    *forcible = 0;

    hash = ngx_crc32_short(key, key_len);

    switch (value_type) {

    case SHDICT_TSTRING:
        /* do nothing */
        break;

    case SHDICT_TNUMBER:
        dd("num value: %lf", num_value);
        str_value_buf = (u_char *) &num_value;
        str_value_len = sizeof(double);
        break;

    case SHDICT_TBOOLEAN:
        c = num_value ? 1 : 0;
        str_value_buf = &c;
        str_value_len = sizeof(u_char);
        break;

    case LUA_TNIL:
        if (op & (NGX_HTTP_LUA_SHDICT_ADD|NGX_HTTP_LUA_SHDICT_REPLACE)) {
            *errmsg = "attempt to add or replace nil values";
            return NGX_ERROR;
        }

        str_value_buf = NULL;
        str_value_len = 0;
        break;

    default:
        *errmsg = "unsupported value type";
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key, key_len, &sd);

    dd("lookup returns %d", (int) rc);

    if (op & NGX_HTTP_LUA_SHDICT_REPLACE) {

        if (rc == NGX_DECLINED || rc == NGX_DONE) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            *errmsg = "not found";
            return NGX_DECLINED;
        }

        /* rc == NGX_OK */

        goto replace;
    }

    if (op & NGX_HTTP_LUA_SHDICT_ADD) {

        if (rc == NGX_OK) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            *errmsg = "exists";
            return NGX_DECLINED;
        }

        if (rc == NGX_DONE) {
            /* exists but expired */

            dd("go to replace");
            goto replace;
        }

        /* rc == NGX_DECLINED */

        dd("go to insert");
        goto insert;
    }

    if (rc == NGX_OK || rc == NGX_DONE) {

        if (value_type == LUA_TNIL) {
            goto remove;
        }

replace:

        if (str_value_buf
            && str_value_len == (size_t) sd->value_len
            && sd->value_type != SHDICT_TLIST
            && sd->value_type != SHDICT_TZSET)
        {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict set: found old entry and value "
                           "size matched, reusing it");

            ngx_queue_remove(&sd->queue);
            ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

            sd->key_len = (u_short) key_len;

            if (exptime > 0) {
                tp = ngx_timeofday();
                sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                              + (uint64_t) exptime;

            } else {
                sd->expires = 0;
            }

            sd->user_flags = user_flags;

            sd->value_len = (uint32_t) str_value_len;

            dd("setting value type to %d", value_type);

            sd->value_type = (uint8_t) value_type;

            p = ngx_copy(sd->data, key, key_len);
            ngx_memcpy(p, str_value_buf, str_value_len);

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return NGX_OK;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict set: found old entry but value size "
                       "NOT matched, removing it first");

remove:

        if (sd->value_type == SHDICT_TLIST) {
            ngx_http_lua_shdict_free_list(ctx, sd);
        }

        if (sd->value_type == SHDICT_TZSET) {
            ngx_http_lua_shdict_free_rbtree(ctx, sd);
        }

        ngx_queue_remove(&sd->queue);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);

    }

insert:

    /* rc == NGX_DECLINED or value size unmatch */

    if (str_value_buf == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict set: creating a new entry");

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key_len
        + str_value_len;

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {

        if (op & NGX_HTTP_LUA_SHDICT_SAFE_STORE) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            *errmsg = "no memory";
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict set: overriding non-expired items "
                       "due to memory shortage for entry \"%*s\"", key_len,
                       key);

        for (i = 0; i < 30; i++) {
            if (ngx_http_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }

            *forcible = 1;

            node = ngx_slab_alloc_locked(ctx->shpool, n);
            if (node != NULL) {
                goto allocated;
            }
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        *errmsg = "no memory";
        return NGX_ERROR;
    }

allocated:

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    node->key = hash;
    sd->key_len = (u_short) key_len;

    if (exptime > 0) {
        tp = ngx_timeofday();
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) exptime;

    } else {
        sd->expires = 0;
    }

    sd->user_flags = user_flags;
    sd->value_len = (uint32_t) str_value_len;
    dd("setting value type to %d", value_type);
    sd->value_type = (uint8_t) value_type;

    p = ngx_copy(sd->data, key, key_len);
    ngx_memcpy(p, str_value_buf, str_value_len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);
    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


int
ngx_http_lua_ffi_shdict_get(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len, int *value_type, u_char **str_value_buf,
    size_t *str_value_len, double *num_value, int *user_flags,
    int get_stale, int *is_stale, char **err)
{
    ngx_str_t                    name;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_str_t                    value;

    if (zone == NULL) {
        return NGX_ERROR;
    }

    *err = NULL;

    ctx = zone->data;
    name = ctx->name;

    hash = ngx_crc32_short(key, key_len);

#if (NGX_DEBUG)
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%*s\" in shared dict \"%V\"", key_len,
                   key, &name);
#endif /* NGX_DEBUG */

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    if (!get_stale) {
        ngx_http_lua_shdict_expire(ctx, 1);
    }
#endif

    rc = ngx_http_lua_shdict_lookup(zone, hash, key, key_len, &sd);

    dd("shdict lookup returns %d", (int) rc);

    if (rc == NGX_DECLINED || (rc == NGX_DONE && !get_stale)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        *value_type = LUA_TNIL;
        return NGX_OK;
    }

    /* rc == NGX_OK || (rc == NGX_DONE && get_stale) */

    *value_type = sd->value_type;

    dd("data: %p", sd->data);
    dd("key len: %d", (int) sd->key_len);

    value.data = sd->data + sd->key_len;
    value.len = (size_t) sd->value_len;

    if (*str_value_len < (size_t) value.len) {
        if (*value_type == SHDICT_TBOOLEAN) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_ERROR;
        }

        if (*value_type == SHDICT_TSTRING) {
            *str_value_buf = malloc(value.len);
            if (*str_value_buf == NULL) {
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                return NGX_ERROR;
            }
        }
    }

    switch (*value_type) {

    case SHDICT_TSTRING:
        *str_value_len = value.len;
        ngx_memcpy(*str_value_buf, value.data, value.len);
        break;

    case SHDICT_TNUMBER:

        if (value.len != sizeof(double)) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "bad lua number value size found for key %*s "
                          "in shared_dict %V: %z", key_len, key,
                          &name, value.len);
            return NGX_ERROR;
        }

        *str_value_len = value.len;
        ngx_memcpy(num_value, value.data, sizeof(double));
        break;

    case SHDICT_TBOOLEAN:

        if (value.len != sizeof(u_char)) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "bad lua boolean value size found for key %*s "
                          "in shared_dict %V: %z", key_len, key, &name,
                          value.len);
            return NGX_ERROR;
        }

        ngx_memcpy(*str_value_buf, value.data, value.len);
        break;

    case SHDICT_TLIST:

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        *err = "value is a list";
        return NGX_ERROR;

    case SHDICT_TZSET:

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        *err = "value is a zset";
        return NGX_ERROR;

    default:

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "bad value type found for key %*s in "
                      "shared_dict %V: %d", key_len, key, &name,
                      *value_type);
        return NGX_ERROR;
    }

    *user_flags = sd->user_flags;
    dd("user flags: %d", *user_flags);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (get_stale) {

        /* always return value, flags, stale */

        *is_stale = (rc == NGX_DONE);
        return NGX_OK;
    }

    return NGX_OK;
}


int
ngx_http_lua_ffi_shdict_incr(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len, double *value, char **err, int has_init, double init,
    long init_ttl, int *forcible)
{
    int                          i, n;
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_time_t                  *tp = NULL;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;
    double                       num;
    ngx_rbtree_node_t           *node;
    u_char                      *p;

    if (zone == NULL) {
        return NGX_ERROR;
    }

    if (init_ttl > 0) {
        tp = ngx_timeofday();
    }

    ctx = zone->data;

    *forcible = 0;

    hash = ngx_crc32_short(key, key_len);

    dd("looking up key %.*s in shared dict %.*s", (int) key_len, key,
       (int) ctx->name.len, ctx->name.data);

    ngx_shmtx_lock(&ctx->shpool->mutex);
#if 1
    ngx_http_lua_shdict_expire(ctx, 1);
#endif
    rc = ngx_http_lua_shdict_lookup(zone, hash, key, key_len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        if (!has_init) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            *err = "not found";
            return NGX_ERROR;
        }

        /* add value */
        num = *value + init;

        if (rc == NGX_DONE) {

            /* found an expired item */

            if ((size_t) sd->value_len == sizeof(double)
                && sd->value_type != SHDICT_TLIST
                && sd->value_type != SHDICT_TZSET)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                               "lua shared dict incr: found old entry and "
                               "value size matched, reusing it");

                ngx_queue_remove(&sd->queue);
                ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

                dd("go to setvalue");
                goto setvalue;
            }

            dd("go to remove");
            goto remove;
        }

        dd("go to insert");
        goto insert;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TNUMBER || sd->value_len != sizeof(double)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        *err = "not a number";
        return NGX_ERROR;
    }

    ngx_queue_remove(&sd->queue);
    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

    dd("setting value type to %d", (int) sd->value_type);

    p = sd->data + key_len;

    ngx_memcpy(&num, p, sizeof(double));
    num += *value;

    ngx_memcpy(p, (double *) &num, sizeof(double));

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    *value = num;
    return NGX_OK;

remove:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict incr: found old entry but value size "
                   "NOT matched, removing it first");

    if (sd->value_type == SHDICT_TLIST) {
        ngx_http_lua_shdict_free_list(ctx, sd);
    }

    if (sd->value_type == SHDICT_TZSET) {
        ngx_http_lua_shdict_free_rbtree(ctx, sd);
    }

    ngx_queue_remove(&sd->queue);

    node = (ngx_rbtree_node_t *)
               ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

    ngx_rbtree_delete(&ctx->sh->rbtree, node);

    ngx_slab_free_locked(ctx->shpool, node);

insert:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict incr: creating a new entry");

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_lua_shdict_node_t, data)
        + key_len
        + sizeof(double);

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict incr: overriding non-expired items "
                       "due to memory shortage for entry \"%*s\"", key_len,
                       key);

        for (i = 0; i < 30; i++) {
            if (ngx_http_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }

            *forcible = 1;

            node = ngx_slab_alloc_locked(ctx->shpool, n);
            if (node != NULL) {
                goto allocated;
            }
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        *err = "no memory";
        return NGX_ERROR;
    }

allocated:

    sd = (ngx_http_lua_shdict_node_t *) &node->color;

    node->key = hash;

    sd->key_len = (u_short) key_len;

    sd->value_len = (uint32_t) sizeof(double);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

setvalue:

    sd->user_flags = 0;

    if (init_ttl > 0) {
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) init_ttl;

    } else {
        sd->expires = 0;
    }

    dd("setting value type to %d", LUA_TNUMBER);

    sd->value_type = (uint8_t) LUA_TNUMBER;

    p = ngx_copy(sd->data, key, key_len);
    ngx_memcpy(p, (double *) &num, sizeof(double));

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    *value = num;
    return NGX_OK;
}


int
ngx_http_lua_ffi_shdict_flush_all(ngx_shm_zone_t *zone)
{
    ngx_queue_t                 *q;
    ngx_http_lua_shdict_node_t  *sd;
    ngx_http_lua_shdict_ctx_t   *ctx;

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    for (q = ngx_queue_head(&ctx->sh->lru_queue);
         q != ngx_queue_sentinel(&ctx->sh->lru_queue);
         q = ngx_queue_next(q))
    {
        sd = ngx_queue_data(q, ngx_http_lua_shdict_node_t, queue);
        sd->expires = 1;
    }

    ngx_http_lua_shdict_expire(ctx, 0);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_shdict_peek(ngx_shm_zone_t *shm_zone, ngx_uint_t hash,
    u_char *kdata, size_t klen, ngx_http_lua_shdict_node_t **sdp)
{
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    ctx = shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sd = (ngx_http_lua_shdict_node_t *) &node->color;

        rc = ngx_memn2cmp(kdata, sd->data, klen, (size_t) sd->key_len);

        if (rc == 0) {
            *sdp = sd;

            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *sdp = NULL;

    return NGX_DECLINED;
}


int
ngx_http_lua_ffi_shdict_get_ttl(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len)
{
    uint32_t                     hash;
    uint64_t                     now;
    uint64_t                     expires;
    ngx_int_t                    rc;
    ngx_time_t                  *tp;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    if (zone == NULL) {
        return NGX_ERROR;
    }

    ctx = zone->data;
    hash = ngx_crc32_short(key, key_len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_http_lua_shdict_peek(zone, hash, key, key_len, &sd);

    if (rc == NGX_DECLINED) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_DECLINED;
    }

    /* rc == NGX_OK */

    expires = sd->expires;

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (expires == 0) {
        return 0;
    }

    tp = ngx_timeofday();
    now = (uint64_t) tp->sec * 1000 + tp->msec;

    return expires - now;
}


int
ngx_http_lua_ffi_shdict_set_expire(ngx_shm_zone_t *zone, u_char *key,
    size_t key_len, int exptime)
{
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_time_t                  *tp = NULL;
    ngx_http_lua_shdict_ctx_t   *ctx;
    ngx_http_lua_shdict_node_t  *sd;

    if (zone == NULL) {
        return NGX_ERROR;
    }

    if (exptime > 0) {
        tp = ngx_timeofday();
    }

    ctx = zone->data;
    hash = ngx_crc32_short(key, key_len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_http_lua_shdict_peek(zone, hash, key, key_len, &sd);

    if (rc == NGX_DECLINED) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_DECLINED;
    }

    /* rc == NGX_OK */

    if (exptime > 0) {
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) exptime;

    } else {
        sd->expires = 0;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


size_t
ngx_http_lua_ffi_shdict_capacity(ngx_shm_zone_t *zone)
{
    return zone->shm.size;
}


#    if nginx_version >= 1011007
size_t
ngx_http_lua_ffi_shdict_free_space(ngx_shm_zone_t *zone)
{
    size_t                       bytes;
    ngx_http_lua_shdict_ctx_t   *ctx;

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);
    bytes = ctx->shpool->pfree * ngx_pagesize;
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return bytes;
}
#    endif /* nginx_version >= 1011007 */


#endif /* NGX_LUA_NO_FFI_API */


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
