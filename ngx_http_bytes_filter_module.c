
/*
 * Copyright (C) Maxim Dounin
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t         enable;
} ngx_http_bytes_conf_t;


typedef struct {
    off_t              start;
    off_t              end;
} ngx_http_bytes_t;


typedef struct {
    off_t              offset;
    ngx_array_t        ranges;
    ngx_http_bytes_t  *range;
} ngx_http_bytes_ctx_t;


static void *ngx_http_bytes_create_conf(ngx_conf_t *cf);
static char *ngx_http_bytes_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_bytes_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_bytes_commands[] = {

    { ngx_string("bytes"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_bytes_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_bytes_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_bytes_init,           /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_bytes_create_conf,    /* create location configuration */
    ngx_http_bytes_merge_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_bytes_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_bytes_module_ctx,    /* module context */
    ngx_http_bytes_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_bytes_header_filter(ngx_http_request_t *r)
{
    u_char                 *p, *last;
    off_t                   start, end, len;
    ngx_uint_t              suffix, bad;
    ngx_http_bytes_t       *range;
    ngx_http_bytes_conf_t  *conf;
    ngx_http_bytes_ctx_t   *ctx;
    enum {
        sw_start = 0,
        sw_first_byte_pos,
        sw_first_byte_pos_n,
        sw_last_byte_pos,
        sw_last_byte_pos_n,
        sw_done
    } state = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_bytes_filter_module);

    if (!conf->enable || r->args.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    p = (u_char *) ngx_strnstr(r->args.data, "bytes=", r->args.len);

    if (p == NULL) {
        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bytes header filter: r %p", r);

    p += sizeof("bytes=") - 1;
    last = r->args.data + r->args.len;

    /* create context */

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_bytes_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&ctx->ranges, r->pool, 1, sizeof(ngx_http_bytes_t))
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    /*
     * bytes= contain ranges compatible with RFC 2616, "14.35.1 Byte Ranges",
     * but no whitespaces permitted
     */

    bad = 0;
    len = 0;
    suffix = 0;
    start = 0;
    end = 0;

    while (p < last) {

        switch (state) {

        case sw_start:
        case sw_first_byte_pos:
            if (*p == '-') {
                p++;
                suffix = 1;
                state = sw_last_byte_pos;
                break;
            }
            state = sw_first_byte_pos_n;

            /* fall through */

        case sw_first_byte_pos_n:
            if (*p == '-') {
                p++;
                state = sw_last_byte_pos;
                break;
            }
            if (*p < '0' || *p > '9') {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "bytes header filter: unexpected char '%c'"
                               " (expected first-byte-pos)", *p);
                bad = 1;
                break;
            }
            start = start * 10 + *p - '0';
            p++;
            break;

        case sw_last_byte_pos:
            if (*p == ',' || *p == '&' || *p == ';') {
                /* no last byte pos, assume end of file */
                end = r->headers_out.content_length_n - 1;
                state = sw_done;
                break;
            }
            end = 0;
            state = sw_last_byte_pos_n;

            /* fall though */

        case sw_last_byte_pos_n:
            if (*p == ',' || *p == '&' || *p == ';') {
                state = sw_done;
                break;
            }
            if (*p < '0' || *p > '9') {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "bytes header filter: unexpected char '%c'"
                               " (expected last-byte-pos)", *p);
                bad = 1;
                break;
            }
            end = end * 10 + *p - '0';
            p++;
            break;

        case sw_done:
            range = ngx_array_push(&ctx->ranges);
            if (range == NULL) {
                return NGX_ERROR;
            }

            if (suffix) {
                start = r->headers_out.content_length_n - end;
                end = r->headers_out.content_length_n - 1;
            }

            /* note: range->end isn't inclusive, while last-byte-pos is */

            range->start = start;
            range->end = end + 1;
            len += range->end - range->start;

            if (*p == ',') {
                p++;
                state = sw_first_byte_pos;
                break;
            }

            goto done;

        }

        if (bad) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "bytes header filter: invalid range specification");
            return ngx_http_next_header_filter(r);
        }
    }

    switch (state) {

    case sw_last_byte_pos:
        end = r->headers_out.content_length_n - 1;

        /* fall through */

    case sw_last_byte_pos_n:
        range = ngx_array_push(&ctx->ranges);
        if (range == NULL) {
            return NGX_ERROR;
        }

        if (suffix) {
            start = r->headers_out.content_length_n - end;
            end = r->headers_out.content_length_n - 1;
        }

        range->start = start;
        range->end = end + 1;
        len += range->end - range->start;

        break;

    default:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "bytes header filter: invalid range specification");
        return ngx_http_next_header_filter(r);

    }

done:
    r->headers_out.content_length_n = len;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_bytes_filter_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bytes header filter: new length %O",
                   r->headers_out.content_length_n);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_bytes_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                  size;
    ngx_uint_t             i;
    ngx_chain_t          **ll, *cl, *dcl;
    ngx_buf_t             *buf, *b;
    ngx_http_bytes_ctx_t  *ctx;
    ngx_http_bytes_t      *range, *last;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_bytes_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    buf = in->buf;

    if (ngx_buf_special(buf)) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bytes body filter: r %p, in %p", r, in);

    range = ctx->ranges.elts;

    for (i = 0; i < ctx->ranges.nelts; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bytes body filter: %O-%O", range->start, range->end);
        range++;
    }

    range = ctx->range;

    if (range == NULL) {
        range = ctx->range = ctx->ranges.elts;
    }

    last = ctx->ranges.elts;
    last += ctx->ranges.nelts;

    /* optimized version for last range and last buffer */

    if (range == last - 1 && buf->last_buf) {

        size = ngx_buf_size(buf);

        if (buf->in_file) {
            if (range->start > ctx->offset) {
                buf->file_pos += range->start - ctx->offset;
            }
            if (range->end < ctx->offset + size) {
                buf->file_last -= ctx->offset + size - range->end;
            }
        }

        if (ngx_buf_in_memory(buf)) {
            if (range->start > ctx->offset) {
                buf->pos += (size_t) (range->start - ctx->offset);
            }
            if (range->end < ctx->offset + size) {
                buf->last -= (size_t) (ctx->offset + size - range->end);
            }
        }

        return ngx_http_next_body_filter(r, in);
    }

    for (ll = &in, cl = in; cl; ll = &cl->next, cl = cl->next,
                                                ctx->offset += size)
    {

        buf = cl->buf;
        size = ngx_buf_size(buf);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bytes body filter: b %d", size);

        if (ngx_buf_special(buf)) {
            /* pass out anyway */
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "bytes body filter: special buffer");
            continue;
        }

next:
        if (range->start > ctx->offset + size) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "bytes body filter: fully ignored buffer");
            *ll = cl->next;
            buf->pos = buf->last;
            continue;
        }

        /* todo: do not create buffers/links if not needed */

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->in_file = buf->in_file;
        b->temporary = buf->temporary;
        b->memory = buf->memory;
        b->mmap = buf->mmap;
        b->file = buf->file;

        if (buf->in_file) {
            b->file_pos = buf->file_pos;
            b->file_last = buf->file_last;
        }

        if (ngx_buf_in_memory(buf)) {
            b->pos = buf->pos;
            b->last = buf->last;
        }

        dcl = ngx_alloc_chain_link(r->pool);
        if (dcl == NULL) {
            return NGX_ERROR;
        }

        *ll = dcl;
        dcl->buf = b;
        dcl->next = cl->next;
        ll = &dcl->next;

        if (buf->last_buf && range == last - 1) {
            b->last_buf = 1;
        }

        if (b->in_file) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "bytes body filter: in file, %O-%O",
                           b->file_pos, b->file_last);

            if (range->start > ctx->offset) {
                b->file_pos += range->start - ctx->offset;
            }
            if (range->end < ctx->offset + size) {
                b->file_last -= ctx->offset + size - range->end;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "bytes body filter: in file fixed, %O-%O",
                           b->file_pos, b->file_last);
        }

        if (ngx_buf_in_memory(b)) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "bytes body filter: in memory, %p-%p",
                           b->pos, b->last);

            if (range->start > ctx->offset) {
                b->pos += (size_t) (range->start - ctx->offset);
            }
            if (range->end < ctx->offset + size) {
                b->last -= (size_t) (ctx->offset + size - range->end);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "bytes body filter: in memory fixed, %p-%p",
                           b->pos, b->last);
        }

        if (range->end < ctx->offset + size) {
            range++;
            if (range < last) {
                goto next;
            }
        }
    }

    return ngx_http_next_body_filter(r, in);
}


static void *
ngx_http_bytes_create_conf(ngx_conf_t *cf)
{
    ngx_http_bytes_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_bytes_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_bytes_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_bytes_conf_t *prev = parent;
    ngx_http_bytes_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_bytes_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_bytes_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_bytes_body_filter;

    return NGX_OK;
}
