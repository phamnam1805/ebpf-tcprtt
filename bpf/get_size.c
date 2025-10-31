#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/types.h>
#include "tcprtt.h"

#define PRINT_FIELD(name) \
    printf("%-12s offset=%-3zu size=%-3zu\n", #name, offsetof(struct hist, name), sizeof(((struct hist *)0)->name))

int main(void) {
    printf("Struct event layout (total size = %zu bytes):\n", sizeof(struct hist));
    printf("--------------------------------------------------\n");

    PRINT_FIELD(latency);
    PRINT_FIELD(cnt);
    PRINT_FIELD(slots);

    return 0;
}