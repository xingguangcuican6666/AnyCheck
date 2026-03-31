#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// 直接读取 ARM64 虚拟计数器寄存器
static inline uint64_t read_cntvct() {
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r" (val));
    return val;
}

// 执行测试的函数
uint64_t test_path_latency(const char *path) {
    struct stat st;
    uint64_t start, end;
    
    // 预热缓存，减少首次加载的 I/O 干扰
    stat(path, &st);
    
    start = read_cntvct();
    // 执行系统调用
    stat(path, &st);
    end = read_cntvct();
    
    return end - start;
}

int main() {
    const char *normal_path = "/system/bin/sh";
    const char *ksu_path = "/system/bin/su"; // KSU 通常会在此路径挂载 Hook
    
    const int iterations = 1000;
    uint64_t normal_total = 0;
    uint64_t ksu_total = 0;

    printf("[*] 正在进行时序采样 (%d 次)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        normal_total += test_path_latency(normal_path);
        ksu_total += test_path_latency(ksu_path);
    }

    printf("\n--- 检测结果 ---\n");
    printf("普通路径平均周期: %llu\n", normal_total / iterations);
    printf("敏感路径平均周期: %llu\n", ksu_total / iterations);
    
    double ratio = (double)ksu_total / normal_total;
    printf("耗时比率 (Ratio): %.2f\n", ratio);

    if (ratio > 1.3) {
        printf("[!] 警告：敏感路径耗时异常偏高，可能存在内核劫持 (KSU/Magisk).\n");
    } else {
        printf("[+] 系统调用响应均匀，未发现明显内核 Hook 痕迹.\n");
    }

    return 0;
}

