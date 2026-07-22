# CHIMERA — Multi-CVE Linux Kernel LPE Exploitation Framework

> **Church of Malware** — ek0ms savi0r

A framework of standalone proof-of-concept exploits targeting July 2026
Linux kernel vulnerabilities. Each exploit in `exploits/` is a single `.c`
file targeting a specific CVE. `chain.c` orchestrates them in dependency
order for a complete low-privilege → root escalation chain.

Every exploit compiles clean with `-Wall -Werror` and was written against
the actual kernel 6.19.x source code.

## Repository Structure

```
chimera/
├── chain.c              ← Orchestrator (run them all or pick phases)
├── chain                ← Compiled binary
├── CHAIN.md             ← This file
├── LICENSE              ← MIT
├── build.sh             ← Build everything
└── exploits/
    ├── cve-2026-53359.c ← KVM shadow paging UAF — highest value
    ├── cve-2026-53341.c ← fhandle UAF / KASLR leak
    ├── cve-2026-53362.c ← IPv6 fragment gap heap overflow
    ├── cve-2026-53374.c ← amdgpu GART physical memory leak
    ├── cve-2026-53389.c ← TCP-AO key use-after-free
    ├── cve-2026-53354.c ← arm64 TLBI stale TLB entries (silicon errata)
    └── tools/
        └── detect.py    ← BPF-based detection for blue team
```

## Quick Start

```bash
# Build everything
./build.sh

# Or build individual exploits
cd exploits
gcc -O2 -o cve-2026-53359 cve-2026-53359.c -lpthread
gcc -O2 -o cve-2026-53341 cve-2026-53341.c -lpthread
gcc -O2 -o cve-2026-53362 cve-2026-53362.c -lpthread
gcc -O2 -o cve-2026-53374 cve-2026-53374.c -ldrm
gcc -O2 -o cve-2026-53389 cve-2026-53389.c -lpthread
gcc -O2 -o cve-2026-53354 cve-2026-53354.c -lpthread

# Check environment
./chain --status

# Run full chain (auto-selects compatible phases)
./chain

# Run specific phases only
./chain --phase 2                    # KASLR leak only
./chain --phase 4                    # KVM escalation only
./chain --phase 2,4                 # leak + escalate
```

## Individual Exploit Details

---

### CVE-2026-53359 — KVM Shadow Paging UAF (CVSS 8.8)

**File:** `exploits/cve-2026-53359.c`
**Target:** Linux 6.19.x x86_64 with KVM enabled
**Requires:** `/dev/kvm` accessible, Intel VT-x or AMD SVM
**Type:** Use-after-free in KVM shadow page table management

**What the bug is:**
The KVM shadow MMU tracks guest page table modifications by maintaining
`struct kvm_mmu_page` entries that shadow guest PDEs/PTEs. Each entry has
a `gfn` (guest frame number) field and a `spt` pointer to the shadow page
table. When `rmap_remove()` is called during memslot deletion, it uses the
`gfn` from `kvm_mmu_page_get_gfn(sp, index)` to locate the rmap head and
remove the SPTE. If the guest PDE was modified from *outside* the guest
(via host-side direct write to guest memory), the calculated `gfn` does
not match the rmap head where the SPTE was inserted. The SPTE is not
removed, the `kvm_mmu_page` is freed while SPTEs still reference its
`spt` page, and `free_page(sp->spt)` returns the 4KB shadow page table
to the page allocator — while stale SPTEs in parent pages still point to it.

**Exploitation:**
1. Create a KVM VM with two memslots (page tables + code)
2. Set up identity-mapped page tables, guest walks them → shadow pages created
3. Host directly writes to guest memory, modifying a PDE to point to a
   different GFN
4. Guest walks again → KVM creates new shadow entries, but `sp->gfn`
   still holds the OLD GFN (it was never updated)
5. Delete the memslot → `rmap_remove()` looks up the rmap using the
   old GFN → can't find the SPTEs → they leak → `free_page(sp->spt)`
6. Reclaim the freed `sp->spt` page with a userspace-controlled allocation
   → fill it with fake SPTEs pointing to arbitrary physical addresses
7. Next KVM shadow walk reads our fake SPTEs → we read/write any
   physical page → overwrite `modprobe_path` or process `cred` → root

**Usage:**
```bash
cd exploits
gcc -O2 -o cve-2026-53359 cve-2026-53359.c -lpthread
./cve-2026-53359 --dry-run     # check prerequisites
./cve-2026-53359 --verbose     # run with debug output
./cve-2026-53359 --kaslr 0xffffffff81000000  # specify KASLR base
```

**Source analysis:** Real struct offsets from `arch/x86/kvm/mmu/mmu.c`
and `mmu_internal.h` kernel 6.19.x. SPTE format matched to KVM's
`make_spte()` and `mmu_spte_get_lockless()`. `rmap_remove()` trigger
path verified against the actual `__gfn_to_memslot()` call chain.

---

### CVE-2026-53341 — fhandle UAF / KASLR Leak (CVSS 7.8)

**File:** `exploits/cve-2026-53341.c`
**Target:** Linux 6.19.x any architecture
**Requires:** No special hardware — any Linux 6.x system
**Type:** Race condition — use-after-free in filesystem handle permission check

**What the bug is:**
`may_decode_fh()` in `fs/fhandle.c` checks the caller's namespace
permissions by accessing `real_mount(root->mnt)->mnt_ns->user_ns`.
The `mnt_ns` pointer is read **without any lock**. A concurrent
`umount(2)` can free the mount namespace between the pointer read and
its dereference. This is a classic read+use race on a RCU-protected
structure that the reader didn't properly protect with rcu_read_lock.

**Exploitation:**
1. Thread A: repeatedly calls `open_by_handle_at()` with a handle
   referencing a frequently-mounted/unmounted filesystem
2. Thread B: repeatedly calls `mount()` + `umount()` on a tmpfs
3. When the race window hits, `may_decode_fh()` reads a `mnt_ns`
   pointer that was just freed by thread B's `umount()`
4. The freed slab can be reallocated with controlled data via a
   `msg_msg` spray — if we control `user_ns` in the fake struct,
   we pass the capability check
5. Even without the spray, the race leaks kernel pointers through
   stale mountinfo entries → we reconstruct KASLR base

**Usage:**
```bash
cd exploits
gcc -O2 -o cve-2026-53341 cve-2026-53341.c -lpthread
./cve-2026-53341              # race the UAF and leak KASLR
./cve-2026-53341 --kaslr      # try to extract KASLR directly
```

**Source analysis:** Based on `fs/fhandle.c` line 325:
```c
ns_capable(real_mount(root->mnt)->mnt_ns->user_ns, CAP_SYS_ADMIN);
```
The unlocked `mnt_ns` dereference is the race window.

---

### CVE-2026-53362 — IPv6 Fragment Gap Heap Overflow (CVSS 7.8)

**File:** `exploits/cve-2026-53362.c`
**Target:** Linux 6.19.x any architecture, IPv6 enabled
**Requires:** `CAP_NET_RAW` (root or `cap_net_raw` ambient)
**Type:** Integer overflow leading to heap buffer overflow

**What the bug is:**
In `__ip6_append_data()` (`net/ipv6/ip6_output.c`), the fragment gap
calculation used when splitting data across multiple fragments:
```c
fraggap = skb->len - maxfraglen;
```
When fragments are crafted with specific sizes and ordered so that
`skb->len` exceeds `maxfraglen`, `fraggap` becomes a large positive
value. This inflates `datalen = length + fraggap`, which propagates
to `copy = min(...)` and eventually `skb_put(skb, copy)` — writing
past the end of the allocated `sk_buff` data buffer.

**Exploitation:**
1. Open a raw IPv6 socket (`AF_INET6, SOCK_RAW`)
2. Send interleaved fragments of specific sizes to create a reassembly
   queue where `skb->len > maxfraglen`
3. The fraggap overflow causes an OOB write via `skb_put()`
4. Pre-place `msg_msg` objects in the adjacent slab via message queue spray
5. The OOB write corrupts a `msg_msg` header's `m_ts` field →
   we can read past the message boundary → info leak
6. With control over `msg_msg->next`, we get a linked-list write primitive

**Usage:**
```bash
cd exploits
gcc -O2 -o cve-2026-53362 cve-2026-53362.c -lpthread
./cve-2026-53362 --spray      # trigger overflow with slab spray detection
./cve-2026-53362              # trigger overflow alone
```

**Source analysis:** Based on `net/ipv6/ip6_output.c` lines 1605-1620.
The `fraggap` calculation wraps when `skb->len > maxfraglen` in the
specific ordering of fragment reassembly.

---

### CVE-2026-53374 — amdgpu GART Physical Memory Leak (CVSS 8.8)

**File:** `exploits/cve-2026-53374.c`
**Target:** Linux 6.19.x x86_64 with AMD GPU (amdgpu driver)
**Requires:** AMD GPU (discrete or APU), `/dev/dri/card*`, `libdrm-dev`
**Type:** Information disclosure via uninitialized GART TLB entries

**What the bug is:**
`amdgpu_gart_table_ram_alloc()` allocates GART (Graphics Address
Remapping Table) pages without zeroing them. When GEM buffer objects
(BOs) are allocated, they get GART entries. When freed, the GART entries
are **not cleared** (no TLB flush), leaving stale physical addresses in
the GART table. A subsequent small BO allocation that reuses the same
GART slot inherits the stale PTE. When userspace reads the BO contents
(via DMA), it sees the stale physical memory contents.

**Exploitation:**
1. Open `/dev/dri/cardN` where N is the amdgpu device
2. Allocate and free large BOs in a spray pattern → creates stale GART
   entries containing physical addresses of kernel pages
3. Allocate small BOs that reuse the same GART entries
4. Map and read the BO contents → scan for physical addresses
   (values in the range `0x...` with valid PFNs)
5. With leaked physical addresses: walk kernel page tables by reading
   physical memory via the GPU's DMA engine, bypassing the MMU
6. Modify PTE entries in physical memory to clear NX or set supervisor
   bit → SMAP/SMEP bypass

**Usage:**
```bash
cd exploits
# Install libdrm first: apt install libdrm-dev
gcc -O2 -o cve-2026-53374 cve-2026-53374.c -ldrm
./cve-2026-53374              # leak physical addresses
./cve-2026-53374 --scan       # scan for specific kernel structures
```

**Source analysis:** Based on `drivers/gpu/drm/amd/amdgpu/amdgpu_gart.c`.
The `alloc` function uses `dma_alloc_coherent()` without `__GFP_ZERO`,
leaving stale data in the GART entries after free-and-reallocate cycles.

---

### CVE-2026-53389 — TCP-AO Key Use-After-Free (CVSS 7.8)

**File:** `exploits/cve-2026-53389.c`
**Target:** Linux 6.19.x with `CONFIG_TCP_AO` enabled
**Requires:** Any Linux 6.x with TCP-AO (common in distro kernels)
**Type:** Use-after-free in TCP authentication option key management

**What the bug is:**
`tcp_ao_delete_key()` with the `del_async` flag frees a `struct tcp_ao_key`
via `kfree_sensitive()` after an RCU grace period. A concurrent key lookup
via `tcp_ao_do_lookup()` or `getsockopt(TCP_AO_GET_KEYS)` can read the
freed key struct before the RCU callback completes if the timing is right.
The `tcp_ao_key` struct (~96-128 bytes, kmalloc-128) contains:
- `tkey[32]` — the traffic key (controlled data)
- `node` — hlist node for the key hash chain (pointers)
- `rcu` — RCU callback head

After the UAF, the freed slab can be reallocated via `setxattr` or
`sendmsg` spray. Controlling `node.next` lets us inject fake entries
into the key hash chain → persistent kernel network struct corruption.

**Exploitation:**
1. Create a TCP connection
2. Thread A: repeatedly add and delete TCP-AO keys with `del_async=1`
3. Thread B: repeatedly call `TCP_AO_GET_KEYS` for all key IDs
4. When the race hits: `getsockopt()` reads freed `tcp_ao_key` memory
5. Reclaim the freed slot with controlled data via `setxattr` spray
6. The fake key persists in the hash chain — network-level backdoor

**Usage:**
```bash
cd exploits
gcc -O2 -o cve-2026-53389 cve-2026-53389.c -lpthread
./cve-2026-53389              # race the UAF
./cve-2026-53389 --persist    # plant a persistence key
```

**Source analysis:** Based on `net/ipv4/tcp_ao.c` lines 1763-1778.
The `tcp_ao_delete_key()` with `del_async` moves key removal to async
context, creating a race window with concurrent lookups.

---

### CVE-2026-53354 — arm64 TLBI Stale TLB Entries (CVSS 8.8)

**File:** `exploits/cve-2026-53354.c`
**Target:** Linux 6.19.x aarch64, affected Arm CPUs
**Requires:** ARM Cortex-X1C/X2/X3/X4 or A710/A715/A720 or Neoverse-N2/V2
**Type:** Silicon erratum — incomplete TLB invalidation

**What the bug is:**
Certain Arm CPUs have an erratum where broadcast TLB invalidation (TLBI)
instructions do **not** fully invalidate all micro-TLB entries across all
cores. When the kernel unmaps a page (e.g., `mprotect(PROT_NONE)` or
`munmap()`), it broadcasts a TLBI to all cores. On affected CPUs, some
cores' micro-TLBs retain the stale mapping. This means a page that the
kernel believes is unmapped can still be accessed from a userspace thread
pinned to the affected core.

**Exploitation:**
1. `mmap()` a page with RW permissions
2. Write a unique marker into the page
3. `mprotect()` to `PROT_NONE` — kernel broadcasts TLBI
4. Fork a child process pinned to each CPU core
5. Child tries to read the page via the stale virtual address
6. If the micro-TLB is stale: read succeeds, returns the marker
7. If TLBI worked correctly: child gets `SIGSEGV`

**For persistence (Phase 5):** If we map a page pointing to a kernel
data structure (via physical mapping tricks), the stale TLB entry gives
us access that survives mprotect/munmap cycles — a persistent backdoor.

**Usage:**
```bash
cd exploits
gcc -O2 -o cve-2026-53354 cve-2026-53354.c -lpthread
./cve-2026-53354              # test for stale TLBs
./cve-2026-53354 --verify     # multi-core verification
```

**Note:** Cross-compile from x86 if deploying to arm64:
```bash
aarch64-linux-gnu-gcc -O2 -o cve-2026-53354 cve-2026-53354.c -lpthread
```

---

## The CHAIN Process

### How chain.c Works

`chain.c` discovers the execution environment, checks prerequisites for
each exploit, and runs compatible phases in dependency order:

```
chain.c
  │
  ├── Phase 1: cve-2026-53362 (IPv6 frag)
  │     ↓ Heap foothold
  │
  ├── Phase 2: cve-2026-53341 (fhandle UAF)
  │     ↓ KASLR base (leaked or from kallsyms)
  │
  ├── Phase 3: cve-2026-53374 (amdgpu GART)
  │     ↓ Physical memory addresses
  │
  ├── Phase 4: cve-2026-53359 (KVM shadow paging)
  │     ↓ Root shell
  │
  └── Phase 5: cve-2026-53389 / cve-2026-53354 (persistence)
        ↓ Persistent backdoor
```

### Phase Dependencies

| Phase | Needs | Produces |
|-------|-------|----------|
| 1 (IPv6 frag) | `CAP_NET_RAW` | Slab foothold, heap corruption primitive |
| 2 (fhandle) | None | `kaslr_base` — kernel base address |
| 3 (amdgpu) | AMD GPU, `kaslr_base` | `phys_page` — physical addresses for SPTE |
| 4 (KVM) | `/dev/kvm`, `kaslr_base` | Root shell — uid 0 |
| 5 (TCP-AO) | Root | Network-level persistence |
| 5b (arm64) | aarch64 CPU | Architectural persistence |

### Running Individual Exploits

Each exploit in `exploits/` is self-contained. You don't need `chain.c`
at all — just compile and run:

```bash
cd exploits
gcc -O2 -o cve-2026-53359 cve-2026-53359.c -lpthread
./cve-2026-53359 --dry-run
./cve-2026-53359
```

The `chain.c` orchestrator is only needed when you want to:
- Run the full escalation chain automatically
- Pass state between phases (e.g., forward KASLR base from phase 2 to phase 4)
- Check environment compatibility for all phases at once

### State Passing Between Phases

`chain.c` passes state between exploits using environment variables and
`/dev/shm/chimera/` files:

```
Phase 2 (fhandle) writes kaslr_base  →  /dev/shm/chimera/kaslr_base
Phase 4 (KVM) reads kaslr_base       ←  /dev/shm/chimera/kaslr_base
  → uses it for: kallsyms lookup, core_pattern addr calculation
```

When an exploit detects a previous phase's output, it adjusts its behavior:
```bash
# With KASLR base, KVM exploit targets specific kernel addresses
./cve-2026-53359 --kaslr 0xffffffff81000000

# Without it, the exploit runs but won't know where kernel structures are
./cve-2026-53359               # will still trigger the UAF
```

### Build Script

```bash
./build.sh    # Builds chain.c + all exploits
```

## Detection

The `tools/detect.py` script uses BPF to detect the specific syscall
sequences for each phase:

```bash
sudo python3 tools/detect.py --bpf       # live monitoring
python3 tools/detect.py --monitor        # log analysis
```

Detection signals per phase:
- **Phase 1:** Unusual IPv6 fragment sizes, fraggap warnings in dmesg
- **Phase 2:** Rapid `name_to_handle_at` + `umount` cycles
- **Phase 3:** GART allocation/free imbalance in amdgpu driver stats
- **Phase 4:** KVM memslot creation/deletion spikes, GFN mismatch WARNs
- **Phase 5:** TCP-AO key add/delete storms, TLBI timing anomalies

## Source References

All struct offsets and trigger paths verified against the following kernel
source files at tag `v6.19`:

| Source | File | Analyzed For |
|--------|------|-------------|
| `arch/x86/kvm/mmu/mmu.c` | `rmap_remove()`, `kvm_mmu_free_shadow_page()`, `kvm_mmu_page_get_gfn()` | CVE-2026-53359 |
| `arch/x86/kvm/mmu/mmu_internal.h` | `struct kvm_mmu_page` layout, `union kvm_mmu_page_role` | CVE-2026-53359 |
| `fs/fhandle.c` | `may_decode_fh()`, `handle_to_path()` | CVE-2026-53341 |
| `net/ipv6/ip6_output.c` | `__ip6_append_data()` frag gap calculation | CVE-2026-53362 |
| `net/ipv4/tcp_ao.c` | `tcp_ao_delete_key()`, `tcp_ao_do_lookup()` | CVE-2026-53389 |
| `drivers/gpu/drm/amd/amdgpu/amdgpu_gart.c` | `amdgpu_gart_table_ram_alloc()`, `amdgpu_gart_bind()` | CVE-2026-53374 |
| `include/uapi/linux/tcp_ao.h` | `tcp_ao_add`, `tcp_ao_del`, `tcp_ao_getsockopt` structs | CVE-2026-53389 |
| `include/uapi/drm/amdgpu_drm.h` | AMDGPU GEM create/mmap IOCTL numbers | CVE-2026-53374 |


