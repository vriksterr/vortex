#include "vmux.c"
#include "aegis256/aegis256.c"

#include <stdio.h>
#include <poll.h>

int
main(int argc, char **argv)
{
    if (argc > 2)
        return -1;

    int client = argc == 2;

    union vmux_sockaddr local = {
        .sin = {
            .sin_family = AF_INET,
            .sin_port = htons(client + 20000),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        },
    };
    unsigned char key[] = "0123456789ABCDEF0123456789ABCDEF";
    int aes = 1;

    struct vmux *vmux = vmux_create(&local, key, &aes);

    if (!vmux) {
        perror("vmux_create");
        return -1;
    }

    if (client) {
        struct vmux_path_conf path_conf = {
            .local = local,
            .remote.sin = {
                .sin_family = AF_INET,
                .sin_port = htons(20000),
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            },
            .state = VMUX_UP,
            .tx_max_rate = 1000 * 1000,
            .rx_max_rate = 1000 * 1000,
            // use default beat, fixed_rate, loss_limit
        };
        if (vmux_set_path(vmux, &path_conf)) {
            perror("vmux_set_path");
            return -1;
        }
    }

    unsigned char buf[1500];

    for (;;) {
        // mandatory, vmux have lot of work to do.
        if (vmux_update(vmux))
            usleep(100000); // don't use all the cpu

        if (client) {
            // when there is data, vmux_recv() is mandatory
            struct pollfd pollfd = {
                .fd = vmux_get_fd(vmux, 0),
                .events = POLLIN,
            };
            switch (poll(&pollfd, 1, 0)) {
            case -1:
                perror("poll");
                return -1;
            case 1:
                if (vmux_recv(vmux, 0, buf, sizeof(buf)) == -1) {
                    perror("vmux_recv");
                    return -1;
                }
            }

            // we can safely call vmux_send()
            // even if the link is not ready
            int r = vmux_send(vmux, argv[1], strlen(argv[1]));

            if (r == -1) {
                if (errno == EAGAIN)
                    continue;

                perror("vmux_send");
                return -1;
            }
            if (r) break;  // we sent everything, bye :)
        } else {
            int r = vmux_recv(vmux, 0, buf, sizeof(buf));

            if (r == -1) {
                if (errno == EAGAIN)
                    continue;

                perror("vmux_recv");
                return -1;
            }
            if (r) {
                buf[r] = 0;
                printf("%s\n", buf);
            }
        }
    }
    vmux_delete(vmux);

    return 0;
}
