#pragma once

#include "../vmux/vmux.h"
#include "../argz/argz.h"

#include <netinet/in.h>

struct vx_argz_addr {
    union vmux_sockaddr sock;
};

void     vx_set_port (union vmux_sockaddr *, uint16_t);
uint16_t vx_get_port (union vmux_sockaddr *);

int vx_toaddr (char *, size_t, union vmux_sockaddr *);
int vx_totime (char *, size_t, unsigned long long);
int vx_torate (char *, size_t, unsigned long long);

void vx_argz_print (const char *);

int vx_argz_percent_suffix (struct argz_ull *, const char *);

int vx_argz_dev     (int argc, char **argv, void *data);
int vx_argz_ifname  (int argc, char **argv, void *data);
int vx_argz_onoff   (int argc, char **argv, void *data);
int vx_argz_addr    (int argc, char **argv, void *data);
int vx_argz_addr_ip (int argc, char **argv, void *data);
