#include <stdint.h>

struct event {
    uint32_t pid;
    char comm[16];
    uint8_t event_type;  // 0 = exec, 1 = exit
    char filename[256];  // 파일명도 전달
};