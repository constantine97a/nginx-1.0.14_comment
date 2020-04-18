
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>

int main() {
    sched_yield();
    return 0;
}

