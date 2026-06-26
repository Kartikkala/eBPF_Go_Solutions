# Solution 2 (allow packets for a specific app on specified port)

### This program is a bit different than the first one. Up until I reached to this solution, I found out modern eBPF developers generally use "vmlinux.h" for using different data structures used by their respective kernel. Although there's a vmlinux.h in this folder, it is generated dynamically for my particular machine (amd64 architecture with linux 7.0.9 kernel version) means the vmlinux.h won't gnerally work on your particular system. For generating vmlinux.h, you would need bpftool on your distribution where you want to run this eBPF code. (See explaination below)

- I generated the <code>vmlinux.h</code> by using bpftool like - <code>sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h</code>
- This require you to have bpftool on your machine, so you will need to check if the package name is same for your particular distribution and if your package manager's repository contains the package.
- After generating vmlinux.h, you can follow instructions from the <code>README.md</code> of this repository's root to generate go bindings and build the binary.
