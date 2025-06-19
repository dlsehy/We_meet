#ifndef __EVENT_H
#define __EVENT_H

// #include <stdint.h> 

struct event {
    __u32 pid;
    __u32 ppid;
    char comm[16];
    __u8 event_type; // 0 = exec, 1 = exit, 2 = open, 3 = tcp_connect
    char filename[256]; // open 용
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
};

#endif