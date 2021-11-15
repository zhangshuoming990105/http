#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <dirent.h>

#include <event2/http.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include <openssl/ssl.h>
#include "ssl_func.h"
#include "http_func.h"

void parse_uri_get_path(struct evhttp_request *req, char *path);

void handle_gen_cb(struct evhttp_request *req, void *arg);

void handle_get_request(struct evhttp_request *req, void *arg);

int handle_post_request(struct evhttp_request *req, char *arg);

struct bufferevent *ssl_bev_cb(struct event_base *base, void *arg);

const char *FILEPATH = "/Users/wangziqi/Desktop/https_server/doc";

int main(int argc, const char *argv[]) {
    int port = 9999;
    SSL_CTX *ctx;
    //initial openssl
    ctx = ssl_init();

    struct event_base *base;
    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Couldn't create an event_base: exiting\n");
        return 1;
    }
    struct evhttp *http = evhttp_new(base);
    if (!http) {
        fprintf(stderr, "couldn't create evhttp. Exiting.\n");
        return 1;
    }
    //使我们创建好的evhttp句柄 支持SSL加密.
    //实际上，加密的动作和解密的动作都已经帮我们自动完成，我们拿到的数据就已经解密
    evhttp_set_bevcb(http, ssl_bev_cb, ctx);

    struct evhttp_bound_socket *handle;
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    if (port <= 0 || port >= 65536) {
        puts("Invalid port\n");
        return 1;
    }
    handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", port);
    if (!handle) {
        fprintf(stderr, "couldn't bind to port %d. Exiting.\n", port);
        return 1;
    }

    evhttp_set_cb(http, "/get", handle_get_request, NULL);
    evhttp_set_gencb(http, handle_gen_cb, NULL);

    event_base_dispatch(base);
    return 0;
}

void handle_gen_cb(struct evhttp_request *req, void *arg) {
    int fd = 0;
    char *path = (char *) malloc(sizeof(char) * 40);
    //debug function
    // echo_request_line(req);
    // echo_request_headers(req);
    // echo_request_body(req);

    parse_uri_get_path(req, path);
    if (!path) {
        evhttp_send_error(req, HTTP_BADREQUEST, 0);
        return;
    }
    //set 'decode_plus' 0, we leave all '+'' characters unchanged.
    char *decoded_path = evhttp_uridecode(path, 0, NULL);
    if (decoded_path == NULL)
        goto err;
    if (strstr(decoded_path, ".."))
        goto err;
    printf("decoded_path = %s\n", decoded_path);

    //get the file path in server
    size_t len = strlen(decoded_path) + strlen(FILEPATH) + 2;
    char *final_path = malloc(len * sizeof(char));
    if (!final_path) {
        perror("malloc\n");
        goto err;
    }
    evutil_snprintf(final_path, len, "%s%s", FILEPATH, decoded_path);
    printf("final_path : %s\n", final_path);

    //get the info of path 
    struct stat st;
    if (stat(final_path, &st) < 0) {
        printf("file path open error\n");
        goto err;
    }
    //this hold the content we will send
    struct evbuffer *filebuffer = evbuffer_new();
    if (S_ISDIR(st.st_mode)) {//it is a directory
        DIR *d;
        struct dirent *dirent;
        const char *trailing_slash = "";

        if (!strlen(path) || path[strlen(path) - 1] != '/')
            trailing_slash = "/";
        if (!(d = opendir(final_path)))
            goto err;
        //display dirent file
        evbuffer_add_printf(filebuffer,
                            "<!DOCTYPE html>\n"
                            "<html>\n <head>\n"
                            "  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n"
                            "  <title>%s</title>\n"
                            "  <base href='%s%s'>\n"
                            " </head>\n"
                            " <body>\n"
                            "  <h1>%s</h1>\n"
                            "  <hr>\n"
                            "  <ul>\n",
                            decoded_path,
                            path,
                            trailing_slash,
                            decoded_path);
        while ((dirent = readdir(d))) {
            const char *name = dirent->d_name;
            evbuffer_add_printf(filebuffer,
                                "    <li><a href=\"%s\">%s</a>\n",
                                name, name);
        }
        //handle upload work
        evbuffer_add_printf(filebuffer,
                            "  </li>\n"
                            "  </ul>\n"
                            "  <hr>\n"
                            "<form action=\"./\" method=\"post\" enctype=\"multipart/form-data\">\n"
                            "<p><input type=\"file\" name=\"upload\"></p>\n"
                            "<p><input type=\"submit\" value=\"submit\"></p>\n"
                            "</form>\n"
                            "</body>\n"
                            "</html>\n"
        );
        if (evhttp_request_get_command(req) == EVHTTP_REQ_POST) {
            if (handle_post_request(req, final_path) == 0) {
                goto err;
            }
        }
        closedir(d);
        evhttp_add_header(evhttp_request_get_output_headers(req),
                          "Content-Type", "text/html");
    } else {//it is a file
        //get file type
        //const char *content_type = get_file_content_type(decoded_path);
        if ((fd = open(final_path, O_RDONLY)) < 0) {
            perror("open file");
            goto err;
        }
        //get the state of file 
        if (fstat(fd, &st) < 0) {
            perror("fstat");
            goto err;
        }
        evhttp_add_header(evhttp_request_get_output_headers(req),
                          "Content-Type", "application/octet-stream");
        evbuffer_add_file(filebuffer, fd, 0, st.st_size);
    }
    //send reply to client
    evhttp_send_reply(req, HTTP_OK, "OK", filebuffer);
    goto done;

    err:
    evhttp_send_error(req, 404, "Document was not found");
    if (fd >= 0)
        close(fd);
    done:
    if (decoded_path)
        free(decoded_path);
    if (final_path)
        free(final_path);
    if (filebuffer)
        evbuffer_free(filebuffer);
}

//此回调负责创建一个ssl连接，并将其包装到openssl bufferevent中，
struct bufferevent *ssl_bev_cb(struct event_base *base, void *arg) {
    struct bufferevent *ssl_bev;
    SSL_CTX *ctx = (SSL_CTX *) arg;

    ssl_bev = bufferevent_openssl_socket_new(base,
                                             -1,
                                             SSL_new(ctx),
                                             BUFFEREVENT_SSL_ACCEPTING,
                                             BEV_OPT_CLOSE_ON_FREE);
    return ssl_bev;
}

//test the form of uri and get the path
//parse a URI-Reference as specified by RFC3986.like
//scheme://[[userinfo]@]foo.com[:port]]/[path][?query][#fragment]
void parse_uri_get_path(struct evhttp_request *req, char *path) {
    const char *uri = evhttp_request_get_uri(req);
    const char *uri_path;
    //parse input uri
    struct evhttp_uri *decoded_uri = evhttp_uri_parse(uri);
    if (!decoded_uri) {
        printf("It's not a good URI. Sending BadRequest\n");
        return;
    } else {
        //get the path
        uri_path = evhttp_uri_get_path(decoded_uri);
        if (!uri_path)
            path = "/";
        else
            printf("path = %s\n", uri_path);
    }
    strcpy(path, uri_path);
    evhttp_uri_free(decoded_uri);
    return;
}

void handle_get_request(struct evhttp_request *req, void *arg) {
    struct evbuffer *outputbuf;

    echo_request_line(req);
    echo_request_headers(req);
    echo_request_body(req);

    outputbuf = evhttp_request_get_output_buffer(req);
    evbuffer_add_printf(outputbuf, "it works! you just request: %s\n", evhttp_request_get_uri(req));
    evhttp_send_reply(req, HTTP_OK, "OK", outputbuf);
}

int handle_post_request(struct evhttp_request *req, char *arg) {
    const char *flname = "filename";
    const char *eol = "\r\n\r\n";
    FILE *fp;
    char buf[4096];
    char filename[20];
    char content[4096];
    char *final_path = arg;
    char *filepath;
    struct evbuffer *inputbuf = evhttp_request_get_input_buffer(req);
    //ger filename
    struct evbuffer_ptr fpos = evbuffer_search(inputbuf, flname, sizeof(flname), NULL);
    printf("filename_pos = %zd\n", fpos.pos);
    evbuffer_copyout_from(inputbuf, &fpos, buf, sizeof(buf));
    printf("%s\n", buf);
    // sscanf(name, "%*[^"]\"%[^"]", filename);
    sscanf(buf, "filename=\"%[^\"]\"", filename);
    printf("%s\n", filename);
    size_t file_len = strlen(final_path) + strlen(filename) + 2;
    filepath = malloc(file_len * sizeof(char));
    sprintf(filepath, "%s%s", final_path, filename);
    printf("%s\n", filepath);
    //get file content
    char *start = strstr(buf, eol) + 4;
    char *end = strstr(start, "----");
    sscanf(start, "%[^----]----", content);
    printf("%s\n", content);
    if ((fp = fopen(filepath, "w+b")) == NULL) {
        printf("Error Open file!\n");
        return 0;
    } else {
        fwrite(content, 1, (int) (end - 2 - start), fp);
    }
    fclose(fp);
    free(filepath);
    return 1;
}