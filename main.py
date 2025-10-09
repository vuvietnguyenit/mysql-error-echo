from bcc import BPF

# Load BPF program
b = BPF(text=r"""
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct data_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    size_t size;
    char msg[64];
};

BPF_PERF_OUTPUT(events);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct data_t data = {};
    struct iov_iter iter = {};
    struct iovec iov = {};
    const struct iovec *iovp = NULL;
    void *base = NULL;

    // Socket info
    bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &sk->__sk_common.skc_dport);
    data.dport = ntohs(data.dport);
    if (data.sport != 3306) {
        return -1; // Filter for HTTP/HTTPS
    }
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);
    data.size = size;

    // Read msg_iter
    bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);

    // Access iter.__iov (works in modern kernels)
    bpf_probe_read_kernel(&iovp, sizeof(iovp), &iter.__iov);
    if (iovp) {
        bpf_trace_printk("%s\n", iovp);
    }
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
""")

# Print output
b.trace_print()
