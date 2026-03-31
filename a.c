#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <pthread.h>
#include <string.h>
#include <math.h>

#define SAMPLE 200000
#define PATH_MAX_LEN 4000

static inline uint64_t read_ticks() {
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r" (val));
    return val;
}

double run_test(const char* p1, const char* p2) {
    struct stat st;
    uint64_t t1 = 0, t2 = 0, s, e;
    for(int i = 0; i < SAMPLE; i++) {
        if (i % 2 == 0) {
            s = read_ticks(); syscall(79, -100, p1, &st, 0); e = read_ticks(); t1 += (e - s);
            s = read_ticks(); syscall(79, -100, p2, &st, 0); e = read_ticks(); t2 += (e - s);
        } else {
            s = read_ticks(); syscall(79, -100, p2, &st, 0); e = read_ticks(); t2 += (e - s);
            s = read_ticks(); syscall(79, -100, p1, &st, 0); e = read_ticks(); t1 += (e - s);
        }
    }
    return (double)t1 / t2;
}

int main() {
    printf("--- KSU 硬件级侧信道哨兵 (Sentinel) ---\n");
    printf("[*] 正在分析内核执行流指纹...\n");

    // 测试 1：短路径（对等长度）
    double short_ratio = run_test("/system/bin/su", "/system/bin/no");
    printf("[1] 短路径对冲 (SU/NO): %.4f\n", short_ratio);

    // 测试 2：长路径（逻辑截断）
    char *p_clean = malloc(PATH_MAX_LEN + 1);
    char *p_heavy = malloc(PATH_MAX_LEN + 1);
    memset(p_clean, 'a', PATH_MAX_LEN); p_clean[PATH_MAX_LEN] = '\0';
    memset(p_heavy, 'a', PATH_MAX_LEN); 
    p_heavy[PATH_MAX_LEN-2] = 's'; p_heavy[PATH_MAX_LEN-1] = 'u'; p_heavy[PATH_MAX_LEN] = '\0';
    
    double long_ratio = run_test(p_heavy, p_clean);
    printf("[2] 长路径截断 (Long-SU/Long-A): %.4f\n", long_ratio);

    // 综合判定逻辑
    printf("\n--- 最终判定矩阵 ---\n");
    int risk_score = 0;

    // 逻辑 A：短路径下 SU 失去了原生缓存优势 (通常原生 < 0.9)
    if (short_ratio > 0.98) {
        printf("[!] 警告: SU 路径的原生缓存加速消失 (疑似被 Hook 抵消)\n");
        risk_score += 40;
    }

    // 逻辑 B：长路径下 SU 异常变快 (通常原生 > 1.1)
    if (long_ratio < 1.05) {
        printf("[!] 警告: 长路径扫描出现异常提前返回 (疑似 LKM 逻辑截断)\n");
        risk_score += 50;
    }

    // 逻辑 C：如果在切换应用时上述比例发生漂移
    printf("[*] 建议: 请切换到前台应用后再运行一次。若两次结果差异 > 15%%，则确定存在 LKM。\n");

    printf("\n内核可信度评分: %d/100 (分数越高风险越大)\n", risk_score);
    if (risk_score >= 80) {
        printf("结论: [发现 KernelSU] 物理层面的执行流与原生内核完全不符。\n");
    } else if (risk_score >= 40) {
        printf("结论: [高度可疑] 存在非对称延迟，建议进行 UID 交叉验证。\n");
    } else {
        printf("结论: [内核纯净] 执行流符合物理预期。\n");
    }

    free(p_clean); free(p_heavy);
    return 0;
}

