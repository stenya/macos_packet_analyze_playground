
#ifndef _DO_BPF_H_
#define _DO_BPF_H_

#include <sys/types.h>

int DoBpf_TEST();

int bpfOpen(const char *interface, int *bpf_fd);
int bpfInjectPacket(int bpf_fd, const void *packet, size_t packet_len);
void bpfClose(int bpf_fd);

#endif //_DO_BPF_H_