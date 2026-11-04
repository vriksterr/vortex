#include "common.h"
#include "argz.h"

volatile sig_atomic_t vx_alarm;
volatile sig_atomic_t vx_reload;
volatile sig_atomic_t vx_quit;

static void
vx_sa_handler(int sig)
{
    switch (sig) {
    case SIGALRM:
        vx_alarm = 1;
        return;
    case SIGHUP:
        vx_reload = 1; /* FALLTHRU */
    default:
        vx_quit = 1;
    }
}

static void
vx_set_signal(void)
{
    struct sigaction sa = {0};

    sa.sa_handler = vx_sa_handler;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

int vx_list    (int, char **, void *);
int vx_show    (int, char **, void *);
int vx_bench   (int, char **, void *);
int vx_bind    (int, char **, void *);
int vx_set     (int, char **, void *);
int vx_keygen  (int, char **, void *);
int vx_path    (int, char **, void *);
int vx_peer    (int, char **, void *);
int vx_version (int, char **, void *);

/* argz_print_help()'s own ARGZ_LEN column (14) is too narrow for entries
 * like "bench multicore fallback", so the bare `vortex` summary uses its
 * own wider column instead of the shared argz_print() path. Descriptions
 * for the real top-level commands still come from z[] itself below -- only
 * the sub-command hint lines are one-off strings, since "bench multicore"
 * etc. aren't top-level argz entries with a description of their own. */
#define VX_HELP_LEN 25

static void
vx_help_line(const char *name, const char *help)
{
    printf("  %-*s  %s\n", VX_HELP_LEN, name, help);
}

static void
vx_print_commands(struct argz *z)
{
    vx_help_line("option", "description");

    for (int i = 0; z[i].name; i++) {
        vx_help_line(z[i].name, z[i].help);

        if (!strcmp(z[i].name, "bench")) {
            vx_help_line("bench multicore",
                        "Bench aggregate multi-core crypto throughput");
            vx_help_line("bench multicore fallback",
                        "Same, using the ChaCha20 fallback cipher");
        } else if (!strcmp(z[i].name, "bind")) {
            vx_help_line("bind qlen",
                        "Set the tun device's tx queue length, e.g. "
                        "bind qlen 1000 (default is the kernel's own)");
            vx_help_line("bind workers",
                        "Number of worker threads, e.g. bind workers 8 "
                        "(default: cores minus one; may exceed the core count)");
            vx_help_line("bind cpus",
                        "Only use these CPU cores, e.g. bind cpus 0-2 or "
                        "0,2 (Linux only; default workers: one per core listed)");
        } else if (!strcmp(z[i].name, "path")) {
            vx_help_line("path watch",
                        "Live-refresh path status every second");
            vx_help_line("path mtu",
                        "Set the fixed MTU to use, e.g. "
                        "path up mtu 1400 (default 1400, no probing)");
            vx_help_line("path connections",
                        "Parallel UDP sub-flows for one path, e.g. "
                        "path up via wan0 connections 4 (default 1, "
                        "requires via)");
        }
    }
}

int
main(int argc, char **argv)
{
    vx_set_signal();

    struct argz z[] = {
        {"list",    "List all tunnels",          vx_list,    .grp = 1},
        {"show",    "Show tunnel information",   vx_show,    .grp = 1},
        {"bench",   "Start a crypto bench",      vx_bench,   .grp = 1},
        {"bind",    "Start a new tunnel",        vx_bind,    .grp = 1},
        {"set",     "Change tunnel properties",  vx_set,     .grp = 1},
        {"keygen",  "Generate a new secret key", vx_keygen,  .grp = 1},
        {"path",    "Manage paths",              vx_path,    .grp = 1},
        {"peer",    "Manage clients of a multi-client tunnel", vx_peer, .grp = 1},
        {"version", "Show version",              vx_version, .grp = 1},
        {0}};

    if (argc == 1) {
        vx_print_commands(z);
        return 0;
    }
    return argz_main(argc, argv, z);
}
