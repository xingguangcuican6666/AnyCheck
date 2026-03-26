#include <jni.h>
#include <time.h>
#include <android/log.h>

#define LOG_TAG "HMA_ColdHot"
#define TEST_COUNT 50

static long get_now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

void run_cold_hot_analysis(JNIEnv *env, jobject pm_obj, jmethodID mid, const char* pkg_name) {
    jstring j_pkg = (*env)->NewStringUTF(env, pkg_name);
    long cold_time = 0;
    long hot_total = 0;

    for (int i = 0; i < TEST_COUNT; i++) {
        long start = get_now_ns();
        (*env)->CallObjectMethod(env, pm_obj, mid, j_pkg, 0);
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        long duration = get_now_ns() - start;

        if (i == 0) {
            cold_time = duration; // 抓取第一次（冷启动）
        } else {
            hot_total += duration; // 累加后续（热启动）
        }
    }

    long hot_avg = hot_total / (TEST_COUNT - 1);
    float ratio = (float)cold_time / (hot_avg > 0 ? hot_avg : 1);

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,
        "目标: %-25s | Cold: %6ld | HotAvg: %6ld | Ratio: %.2f",
        pkg_name, cold_time, hot_avg, ratio);

    (*env)->DeleteLocalRef(env, j_pkg);
}

JNIEXPORT void JNICALL
Java_com_example_baseapp_MainActivity_testColdHot(JNIEnv *env, jobject thiz) {
    jclass context_cls = (*env)->GetObjectClass(env, thiz);
    jmethodID get_pm_mid = (*env)->GetMethodID(env, context_cls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pm_obj = (*env)->CallObjectMethod(env, thiz, get_pm_mid);
    if (!pm_obj) return;
    jclass pm_cls = (*env)->GetObjectClass(env, pm_obj);
    jmethodID get_info_mid = (*env)->GetMethodID(env, pm_cls, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "========== 冷热启动差异分析 ==========");
    run_cold_hot_analysis(env, pm_obj, get_info_mid, "com.android.settings");
    run_cold_hot_analysis(env, pm_obj, get_info_mid, "com.random.fake.pkg.666");
    run_cold_hot_analysis(env, pm_obj, get_info_mid, "com.topjohnwu.magisk");
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "====================================");
}

