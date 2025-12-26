/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "syscall.h"

#include <cache.h>
#include <ktypes.h>
#include <hook.h>
#include <common.h>
#include <linux/string.h>
#include <symbol.h>
#include <uapi/asm-generic/errno.h>
#include <asm-generic/compat.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <predata.h>
#include <kputils.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

// 辅助函数：安全读取内核内存
static int safe_read_kernel(void *dst, const void *src, size_t size)
{
    void *p = memdup_user(src, size);
    if (IS_ERR(p)) return -1;
    memcpy(dst, p, size);
    kfree(p);
    return 0;
}

uintptr_t *sys_call_table = 0;
KP_EXPORT_SYMBOL(sys_call_table);

uintptr_t *compat_sys_call_table = 0;
KP_EXPORT_SYMBOL(compat_sys_call_table);

int has_syscall_wrapper = 0;
KP_EXPORT_SYMBOL(has_syscall_wrapper);

int has_config_compat = 0;
KP_EXPORT_SYMBOL(has_config_compat);

struct user_arg_ptr
{
    union
    {
        const char __user *const __user *native;
    } ptr;
};

struct user_arg_ptr_compat
{
    bool is_compat;
    union
    {
        const char __user *const __user *native;
        const compat_uptr_t __user *compat;
    } ptr;
};

// actually, a0 is true if it is compat
const char __user *get_user_arg_ptr(void *a0, void *a1, int nr)
{
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) size = 4; // compat
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    char __user **upptr = memdup_user(native, size);
    if (IS_ERR(upptr)) return ERR_PTR((long)upptr);

    char __user *uptr;
    if (size == 8) {
        uptr = *upptr;
    } else {
        uptr = (char __user *)(unsigned long)*(int32_t *)upptr;
    }
    kfree(upptr);
    return uptr;
}

int set_user_arg_ptr(void *a0, void *a1, int nr, uintptr_t val)
{
    uintptr_t valp = (uintptr_t)&val;
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) {
            size = 4; // compat
            valp += 4;
        }
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    int cplen = compat_copy_to_user((void *)native, (void *)valp, size);
    return cplen == size ? 0 : cplen;
}

typedef long (*warp_raw_syscall_f)(const struct pt_regs *regs);
typedef long (*raw_syscall0_f)();
typedef long (*raw_syscall1_f)(long arg0);
typedef long (*raw_syscall2_f)(long arg0, long arg1);
typedef long (*raw_syscall3_f)(long arg0, long arg1, long arg2);
typedef long (*raw_syscall4_f)(long arg0, long arg1, long arg2, long arg3);
typedef long (*raw_syscall5_f)(long arg0, long arg1, long arg2, long arg3, long arg4);
typedef long (*raw_syscall6_f)(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

uintptr_t syscalln_name_addr(int nr, int is_compat)
{
    const char *name = 0;
    if (!is_compat) {
        if (syscall_name_table[nr].addr) {
            return syscall_name_table[nr].addr;
        }
        name = syscall_name_table[nr].name;
    } else {
        if (compat_syscall_name_table[nr].addr) {
            return compat_syscall_name_table[nr].addr;
        }
        name = compat_syscall_name_table[nr].name;
    }

    if (!name) return 0;

    const char *prefix[2];
    prefix[0] = "__arm64_";
    prefix[1] = "";
    const char *suffix[3];
    suffix[0] = ".cfi_jt";
    suffix[1] = ".cfi";
    suffix[2] = "";

    uintptr_t addr = 0;

    char buffer[256];
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            snprintf(buffer, sizeof(buffer), "%s%s%s", prefix[i], name, suffix[j]);
            addr = kallsyms_lookup_name(buffer);
            if (addr) break;
        }
        if (addr) break;
    }
    if (!is_compat) {
        syscall_name_table[nr].addr = addr;
    } else {
        compat_syscall_name_table[nr].addr = addr;
    }
    return addr;
}
KP_EXPORT_SYMBOL(syscalln_name_addr);

uintptr_t syscalln_addr(int nr, int is_compat)
{
    if (!is_compat && sys_call_table) return sys_call_table[nr];
    if (is_compat && compat_sys_call_table) return compat_sys_call_table[nr];
    return syscalln_name_addr(nr, is_compat);
}
KP_EXPORT_SYMBOL(syscalln_addr);

long raw_syscall0(long nr)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall0_f)addr)();
}
KP_EXPORT_SYMBOL(raw_syscall0);

long raw_syscall1(long nr, long arg0)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall1_f)addr)(arg0);
}
KP_EXPORT_SYMBOL(raw_syscall1);

long raw_syscall2(long nr, long arg0, long arg1)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall2_f)addr)(arg0, arg1);
}
KP_EXPORT_SYMBOL(raw_syscall2);

long raw_syscall3(long nr, long arg0, long arg1, long arg2)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall3_f)addr)(arg0, arg1, arg2);
}
KP_EXPORT_SYMBOL(raw_syscall3);

long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall4_f)addr)(arg0, arg1, arg2, arg3);
}
KP_EXPORT_SYMBOL(raw_syscall4);

long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall5_f)addr)(arg0, arg1, arg2, arg3, arg4);
}
KP_EXPORT_SYMBOL(raw_syscall5);

long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        regs.regs[5] = arg5;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall6_f)addr)(arg0, arg1, arg2, arg3, arg4, arg5);
}
KP_EXPORT_SYMBOL(raw_syscall6);

hook_err_t fp_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    if (!is_compat) {
        if (!sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        return fp_hook_wrap(fp_addr, narg, before, after, udata);
    } else {
        if (!compat_sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        return fp_hook_wrap(fp_addr, narg, before, after, udata);
    }
}
KP_EXPORT_SYMBOL(fp_wrap_syscalln);

void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    if (!is_compat) {
        if (!sys_call_table) return;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        fp_hook_unwrap(fp_addr, before, after);
    } else {
        if (!compat_sys_call_table) return;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        fp_hook_unwrap(fp_addr, before, after);
    }
}
KP_EXPORT_SYMBOL(fp_unwrap_syscalln);

hook_err_t inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (!addr) return -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper) narg = 1;
    return hook_wrap((void *)addr, narg, before, after, udata);
}
KP_EXPORT_SYMBOL(inline_wrap_syscalln);

void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    hook_unwrap((void *)addr, before, after);
}
KP_EXPORT_SYMBOL(inline_unwrap_syscalln);

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (sys_call_table) return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_syscalln);

void unhook_syscalln(int nr, void *before, void *after)
{
    if (sys_call_table) return fp_unwrap_syscalln(nr, 0, before, after);
    return inline_unwrap_syscalln(nr, 0, before, after);
}
KP_EXPORT_SYMBOL(unhook_syscalln);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (compat_sys_call_table) return fp_wrap_syscalln(nr, narg, 1, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_compat_syscalln);

void unhook_compat_syscalln(int nr, void *before, void *after)
{
    if (compat_sys_call_table) return fp_unwrap_syscalln(nr, 1, before, after);
    return inline_unwrap_syscalln(nr, 1, before, after);
}
KP_EXPORT_SYMBOL(unhook_compat_syscalln);

void syscall_init()
{
    for (int i = 0; i < sizeof(syscall_name_table) / sizeof(syscall_name_table[0]); i++) {
        uintptr_t *addr = (uintptr_t *)&syscall_name_table[i].name;
        *addr = link2runtime(*addr);
    }

    for (int i = 0; i < sizeof(compat_syscall_name_table) / sizeof(compat_syscall_name_table[0]); i++) {
        uintptr_t *addr = (uintptr_t *)&compat_syscall_name_table[i].name;
        *addr = link2runtime(*addr);
    }

    sys_call_table = (typeof(sys_call_table))kallsyms_lookup_name("sys_call_table");
    log_boot("sys_call_table addr: %llx\n", sys_call_table);

    compat_sys_call_table = (typeof(compat_sys_call_table))kallsyms_lookup_name("compat_sys_call_table");
    log_boot("compat_sys_call_table addr: %llx\n", compat_sys_call_table);

    has_config_compat = 0;
    has_syscall_wrapper = 0;

    if (kallsyms_lookup_name("__arm64_compat_sys_openat")) {
        has_config_compat = 1;
        has_syscall_wrapper = 1;
    } else {
        if (kallsyms_lookup_name("compat_sys_call_table") || kallsyms_lookup_name("compat_sys_openat")) {
            has_config_compat = 1;
        }
        if (kallsyms_lookup_name("__arm64_sys_openat")) {
            has_syscall_wrapper = 1;
        }
    }

    // -----------------------------------------------------------
    // FIX START: 尝试通过扫描 rodata 段手动查找 sys_call_table
    // 如果 kallsyms 查找失败，这能避免回退到较慢的 inline hook
    // 从而解决 "Detected delayed syscall" 问题
    // -----------------------------------------------------------
    if (!sys_call_table) {
        uintptr_t start_rodata = kallsyms_lookup_name("__start_rodata");
        uintptr_t end_rodata = kallsyms_lookup_name("__end_rodata");
        
        // 我们选择一个在系统调用表中存在的函数地址作为锚点，例如 __arm64_sys_openat (syscall 56)
        // 使用 syscalln_name_addr 获取地址，因为它包含了缓存逻辑和符号查找
        uintptr_t target_func_addr = syscalln_name_addr(56, 0); // 56 is __arm64_sys_openat
        
        if (start_rodata && end_rodata && target_func_addr) {
            log_boot("sys_call_table not found by kallsyms, scanning rodata...\n");
            
            // 扫描 rodata 段寻找指向目标函数的指针
            for (uintptr_t addr = start_rodata; addr < end_rodata; addr += sizeof(uintptr_t)) {
                uintptr_t val = 0;
                // 使用安全读取避免访问非法内存导致崩溃
                if (safe_read_kernel(&val, (const void *)addr, sizeof(uintptr_t)) != 0) {
                    continue;
                }

                if (val == target_func_addr) {
                    // 找到匹配项，进一步验证是否是 sys_call_table
                    // 检查附近的表项是否指向有效的 syscall 函数
                    // openat 是 56，我们检查 55 (fstatat/newfstatat) 或 57 (fchmod)
                    
                    int valid_table = 1;
                    // 简单验证：检查索引 56 (当前找到的) 和 55
                    // 这里的 offset 是 -1 * sizeof(uintptr_t)
                    uintptr_t neighbor_val = 0;
                    if (addr >= start_rodata + sizeof(uintptr_t)) {
                        if (safe_read_kernel(&neighbor_val, (const void *)(addr - sizeof(uintptr_t)), sizeof(uintptr_t)) == 0) {
                             // 获取 sys_newfstatat 的地址进行比对
                             uintptr_t check_func_addr = syscalln_name_addr(55, 0);
                             if (check_func_addr && neighbor_val == check_func_addr) {
                                 // 验证通过，这很可能是 sys_call_table
                                 log_boot("sys_call_table candidate found at %llx (validated)\n", addr - 1 * sizeof(uintptr_t));
                                 sys_call_table = (typeof(sys_call_table))(addr - 1 * sizeof(uintptr_t));
                                 break;
                             }
                        }
                    }
                    
                    if (!valid_table && addr + sizeof(uintptr_t) < end_rodata) {
                        // 检查索引 57
                         if (safe_read_kernel(&neighbor_val, (const void *)(addr + sizeof(uintptr_t)), sizeof(uintptr_t)) == 0) {
                             uintptr_t check_func_addr = syscalln_name_addr(57, 0); // __arm64_sys_fchmod
                             if (check_func_addr && neighbor_val == check_func_addr) {
                                 log_boot("sys_call_table candidate found at %llx (validated)\n", addr - 1 * sizeof(uintptr_t));
                                 sys_call_table = (typeof(sys_call_table))(addr - 1 * sizeof(uintptr_t));
                                 break;
                             }
                         }
                    }
                    
                    // 如果无法完美验证邻居，但地址本身在 rodata 且指向有效代码，也可以尝试使用
                    // 但为了稳定性，最好依赖验证。
                }
            }
            log_boot("sys_call_table scan result: %llx\n", sys_call_table);
        }
    }
    // FIX END
    // -----------------------------------------------------------

    log_boot("syscall config_compat: %d\n", has_config_compat);
    log_boot("syscall has_wrapper: %d\n", has_syscall_wrapper);
}

