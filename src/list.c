#include "common.h"
#include "ctl.h"
#include "argz.h"

int
vx_list(int argc, char **argv, void *data)
{
    int err = argz(argc, argv, NULL);

    if (err)
        return err;

    ctl_foreach(vx_argz_print);

    return 0;
}
