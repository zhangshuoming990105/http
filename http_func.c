#include <stdio.h>
#include <string.h>
#include <event2/http.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include "http_func.h"

static const struct table_entry {
    const char *extension;
    const char *content_type;
} content_type_table[] = {
        {"txt",  "text/plain"},
        {"c",    "text/plain"},
        {"h",    "text/plain"},
        {"html", "text/html"},
        {"htm",  "text/htm"},
        {"css",  "text/css"},
        {"gif",  "image/gif"},
        {"jpg",  "image/jpeg"},
        {"jpeg", "image/jpeg"},
        {"png",  "image/png"},
        {"pdf",  "application/pdf"},
        {"ps",   "application/postscript"},
        {NULL, NULL},
};

const char *get_file_content_type(const char *path) {
    const char *last_period, *extension;
    const struct table_entry *ent;
    last_period = strrchr(path, '.');
    if (!last_period || strchr(last_period, '/'))
        goto not_found; /* no exension */
    extension = last_period + 1;
    for (ent = &content_type_table[0]; ent->extension; ++ent) {
        if (!evutil_ascii_strcasecmp(ent->extension, extension))
            return ent->content_type;
    }
    not_found:
    return "application/misc";
}

void echo_request_line(struct evhttp_request *req) {
    char *cmdtype;
    const char *uri;
    switch (evhttp_request_get_command(req)) {
        case EVHTTP_REQ_GET:
            cmdtype = "GET";
            break;
        case EVHTTP_REQ_POST:
            cmdtype = "POST";
            break;
        case EVHTTP_REQ_HEAD:
            cmdtype = "HEAD";
            break;
        case EVHTTP_REQ_PUT:
            cmdtype = "PUT";
            break;
        case EVHTTP_REQ_DELETE:
            cmdtype = "DELETE";
            break;
        case EVHTTP_REQ_OPTIONS:
            cmdtype = "OPTIONS";
            break;
        case EVHTTP_REQ_TRACE:
            cmdtype = "TRACE";
            break;
        case EVHTTP_REQ_CONNECT:
            cmdtype = "CONNECT";
            break;
        case EVHTTP_REQ_PATCH:
            cmdtype = "PATCH";
            break;
        default:
            cmdtype = "unknown";
            break;
    }
    uri = evhttp_request_get_uri(req);
    printf("Received a %s request for %s(url)\n", cmdtype, uri);
}

void echo_request_headers(struct evhttp_request *req) {
    struct evkeyvalq *headers;
    struct evkeyval *header;
    headers = evhttp_request_get_input_headers(req);
    for (header = headers->tqh_first; header; header = header->next.tqe_next) {
        printf("    %s: %s\n", header->key, header->value);
    }
}

void echo_request_body(struct evhttp_request *req) {
    struct evbuffer *inputbuf;
    size_t body_size;

    inputbuf = evhttp_request_get_input_buffer(req);
    body_size = evbuffer_get_length(inputbuf);
    printf("body_size = %zu\n", body_size);
    puts("body data:\n");
    if (body_size) {
        int n;
        char cbuf[4096];
        evbuffer_copyout(inputbuf, cbuf, body_size);
        printf("%s\n", cbuf);
    }
}