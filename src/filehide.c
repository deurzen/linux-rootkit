#include "filehide.h"
#include "hook.h"


long (*sys_getdents)(unsigned int, struct linux_dirent *, unsigned int);
long (*sys_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);


void
hide_files(void)
{

}

void
unhide_files(void)
{

}
