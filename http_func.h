#ifndef _HTTP_FUNC

#define _HTTP_FUNC

const char *get_file_content_type(const char *path);

void echo_request_line(struct evhttp_request *req);

void echo_request_headers(struct evhttp_request *req);

void echo_request_body(struct evhttp_request *req);

#endif