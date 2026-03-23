#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

/* 系统调用号：ARM64 下的 fstatat */
#define SYS_FSTATAT 79
#define AT_FDCWD -100

int probe(const char *path) {
    struct stat st;
    // 直接用 syscall 穿透 libc hook
    long res = syscall(SYS_FSTATAT, AT_FDCWD, path, &st, 0);
    if (res == 0) return 1;      // 存在且可访问
    if (errno == EACCES) return 1; // 存在但权限拒绝
    return 0;                    // ENOENT 或其他，视为不存在
}

int main() {
    struct stat st_dir;
    
    // 1. 读取总账
    if (stat("/data/user/0", &st_dir) != 0) return 1;
    int physical_count = st_dir.st_nlink - 2;

    // 2. 审计“必然存在”的占位符
    int found = 0;
    found += probe("/data/user/0/com.termux");
    found += probe("/data/user/0/android");
    found += probe("/data/user/0/com.android.shell");
    found += probe("/data/user/0/com.android.settings");

    // 3. 判定
    // 注意：如果物理坑位 > 我们能探测到的所有合法项，说明有“幽灵”
    if (physical_count > found) {
        printf("🚨 [DETECTED] 发现物理真空！\n");
        printf("📊 内核账本: %d, 实地发现: %d\n", physical_count, found);
        printf("⚠️ 环境已被 HMA/Magisk 篡改。\n");
        return 0xff;
    }

    printf("✅ [CLEAN] 账目一致。\n");
    return 0;
}
