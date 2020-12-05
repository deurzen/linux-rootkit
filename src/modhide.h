#ifndef _GROUP7_MODHIDE_H
#define _GROUP7_MODHIDE_H

void hide_module(void);
void unhide_module(void);
void rb_add(struct kernfs_node *);
int nodecmp(struct kernfs_node *, const unsigned int, const char *, const void *);

#endif//_GROUP7_MODHIDE_H
