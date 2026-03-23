#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/stat.h>

#define SYS_PROBE_STAT 79
#define AT_FDCWD -100

int main(int argc, char *argv[]) {
    if (argc < 2) return -1;

    const char *path = argv[1];
    struct stat st; // 提供一个真实的缓冲区，防止 EFAULT
    long res;

    // 再次尝试系统调用
    res = syscall(SYS_PROBE_STAT, AT_FDCWD, path, &st, 0);

    if (res == 0) {
        return 0; // 成功访问
    }

    // 打印具体的 errno 辅助调试 (可选，为了自动化你可以注释掉)
    // printf("Path: %s, Errno: %d\n", path, errno);

    if (errno == 13) { // EACCES (Permission Denied)
        return 1;
    } else if (errno == 2) { // ENOENT (No such file)
        return 2;
    } else {
        return errno; // 返回原始错误码，比如 14 是 EFAULT
    }
}
