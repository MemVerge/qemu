/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2024 MemVerge Inc.
 *
 */

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>

struct mhsld_state {
    uint8_t nr_heads;
    uint8_t nr_lds;
    uint8_t ldmap[65536];
};

int main(int argc, char *argv[])
{
    int shmid = 0;
    uint32_t sections = 0;
    uint32_t section_size = 0;
    uint32_t heads = 0;
    struct mhsld_state *mhsld_state = NULL;
    size_t state_size;
    uint8_t i;

    if (argc != 3) {
        printf("usage: init_mhsld <heads> <shmid>\n"
                "\theads         : number of heads on the device\n"
                "\tshmid         : /tmp/mytoken.tmp\n\n"
                "It is recommended your shared memory region is at least 128kb\n");
        return -1;
    }

    /* must have at least 1 head */
    heads = (uint32_t)atoi(argv[1]);
    if (heads == 0 || heads > 32) {
        printf("bad heads argument (1-32)\n");
        return -1;
    }

    shmid = (uint32_t)atoi(argv[2]);
    if (shmid == 0) {
        printf("bad shmid argument\n");
        return -1;
    }

    mhsld_state = shmat(shmid, NULL, 0);
    if (mhsld_state == (void *)-1) {
        printf("Unable to attach to shared memory\n");
        return -1;
    }

    /* Initialize the mhsld_state */
    state_size = sizeof(struct mhsld_state) + (sizeof(uint32_t) * sections);
    memset(mhsld_state, 0, state_size);
    mhsld_state->nr_heads = heads;
    mhsld_state->nr_lds = heads;

    memset(&mhsld_state->ldmap, '\xff', sizeof(mhsld_state->ldmap));
    for (i = 0; i < heads; i++) {
        mhsld_state->ldmap[i] = i;
    }

    printf("mhsld initialized\n");
    shmdt(mhsld_state);
    return 0;
}
