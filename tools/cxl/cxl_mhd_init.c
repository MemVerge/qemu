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

struct mhd_state {
    uint8_t nr_heads;
    uint8_t nr_lds;
    uint8_t ldmap[];
};

int main(int argc, char *argv[]) {
    int shmid = 0;
    uint32_t heads = 0;
    struct mhd_state* mhd_state = 0;
    uint8_t i;

    if (argc != 3) {
        printf("usage: cxl_mhd_init <heads> <shmid>\n"
                "\theads         : number of heads on the device\n"
                "\tshmid         : /tmp/mytoken.tmp\n");
        return -1;
    }

    // must have at least 1 head
    heads = (uint32_t)atoi(argv[1]);
    if (heads == 0 || heads > 32) {
        printf("bad heads argument (1-32)\n");
        return -1;
    }

    shmid = (uint32_t)atoi(argv[2]);
    if (shmid== 0) {
        printf("bad shmid argument\n");
        return -1;
    }

    mhd_state = shmat(shmid, NULL, 0);
    if (mhd_state == (void*)-1) {
        printf("Unable to attach to shared memory\n");
        return -1;
    }

    // Initialize the mhd_state
    size_t mhd_state_size = sizeof(struct mhd_state) + (sizeof(uint8_t) * heads);
    memset(mhd_state, 0, mhd_state_size);
    mhd_state->nr_heads = heads;
    mhd_state->nr_lds = heads;

    // Head ID == LD ID for now
    for (i = 0; i < heads; i++)
        mhd_state->ldmap[i] = i;

    printf("mhd initialized\n");
    shmdt(mhd_state);
    return 0;
}
