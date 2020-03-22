#include "iplayer.h"

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int
main(int argc, char **argv)
{
    void *handle;
    typedef IPlayer* (t_create_player)();
    char *error;

   handle = dlopen("./libplayer.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }

   dlerror();    /* Clear any existing error */

   t_create_player* create_player = (t_create_player*)dlsym(handle, "create_player");

   if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }

    IPlayer* p = create_player();
    printf("hello %s\n", p->GetName());

    dlclose(handle);
    exit(EXIT_SUCCESS);
}