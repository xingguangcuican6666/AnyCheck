package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import com.anycheck.app.R
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Comprehensive KernelSU detection engine.
 * Implements all known detection methods used by the security community.
 */
class KernelSUDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkKernelSUFiles(),
        checkKernelSUPackages(),
        checkKernelVersion(),
        checkKernelSUDatabase(),
        checkKernelSUMountPoints(),
        checkKernelSUProcesses(),
        checkKernelSUSyscall(),
        checkKernelSUProps(),
        checkKernelSULoopDevice()
    )

    /** Check 1: KernelSU-specific files */
    private fun checkKernelSUFiles(): DetectionResult {
        val ksuFiles = listOf(
            "/data/adb/ksud",
            "/data/adb/ksu",
            "/data/adb/ksu/bin/busybox",
            "/data/adb/ksu/bin/ksud",
            "/data/adb/ksu/modules",
            "/data/adb/ksu/modules_update",
            "/data/adb/ksu.db",
            "/system/bin/ksud",
            "/system/xbin/ksud",
            "/dev/.ksu_bind_mnt"
        )
        val found = ksuFiles.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "ksu_files",
                name = context.getString(R.string.chk_ksu_files_name),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ksu_files_desc),
                detailedReason = context.getString(R.string.chk_ksu_files_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_ksu_files_solution),
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ksu_files",
                name = context.getString(R.string.chk_ksu_files_name_nd),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ksu_files_desc_nd),
                detailedReason = context.getString(R.string.chk_ksu_files_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 2: KernelSU app packages */
    private fun checkKernelSUPackages(): DetectionResult {
        val ksuPackages = listOf(
            "me.weishu.kernelsu",           // Official KernelSU Manager
            "me.weishu.kernelsu.debug",
            "com.rifsxd.ksunext",           // KsuNext
            "io.github.tiann.ksunext",
            "com.rsuntk.ksunext"
        )
        val found = ksuPackages.filter { packageExists(it) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "ksu_packages",
                name = context.getString(R.string.chk_ksu_packages_name),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ksu_packages_desc),
                detailedReason = context.getString(R.string.chk_ksu_packages_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_ksu_packages_solution),
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ksu_packages",
                name = context.getString(R.string.chk_ksu_packages_name_nd),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ksu_packages_desc_nd),
                detailedReason = context.getString(R.string.chk_ksu_packages_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 3: Kernel version string containing KernelSU version */
    private fun checkKernelVersion(): DetectionResult {
        return try {
            val kernelVersion = File("/proc/version").readText()
            val ksuIndicators = listOf("KernelSU", "ksu", "KERNELSU")
            val found = ksuIndicators.filter { kernelVersion.contains(it, ignoreCase = false) }

            // Also check uname
            var unameOutput = ""
            try {
                val process = Runtime.getRuntime().exec("uname -r")
                unameOutput = BufferedReader(InputStreamReader(process.inputStream)).readLine() ?: ""
            } catch (_: Exception) {}

            val unameFound = ksuIndicators.filter { unameOutput.contains(it, ignoreCase = false) }
            val allFound = (found + unameFound).distinct()

            if (allFound.isNotEmpty()) {
                DetectionResult(
                    id = "ksu_kernel_version",
                    name = context.getString(R.string.chk_ksu_kernel_version_name),
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_ksu_kernel_version_desc),
                    detailedReason = context.getString(R.string.chk_ksu_kernel_version_reason, 
                        allFound.joinToString(", "), kernelVersion.take(100)),
                    solution = context.getString(R.string.chk_ksu_kernel_version_solution),
                    technicalDetail = "Kernel: ${kernelVersion.take(200)}"
                )
            } else {
                DetectionResult(
                    id = "ksu_kernel_version",
                    name = context.getString(R.string.chk_ksu_kernel_version_name_nd),
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_ksu_kernel_version_desc_nd),
                    detailedReason = context.getString(R.string.chk_ksu_kernel_version_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed),
                    technicalDetail = "Kernel: ${kernelVersion.take(100)}"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "ksu_kernel_version",
                name = context.getString(R.string.chk_ksu_kernel_version_name_nd),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ksu_kernel_version_desc_error),
                detailedReason = context.getString(R.string.chk_ksu_kernel_version_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_ksu_kernel_version_solution_error)
            )
        }
    }

    /** Check 4: KernelSU database */
    private fun checkKernelSUDatabase(): DetectionResult {
        val dbPaths = listOf(
            "/data/adb/ksu.db",
            "/data/adb/ksu/ksu.db",
            "/data/adb/ksud.db"
        )
        val found = dbPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "ksu_db",
                name = context.getString(R.string.chk_ksu_db_name),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ksu_db_desc),
                detailedReason = context.getString(R.string.chk_ksu_db_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_ksu_db_solution),
                technicalDetail = "DB paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ksu_db",
                name = context.getString(R.string.chk_ksu_db_name_nd),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ksu_db_desc_nd),
                detailedReason = context.getString(R.string.chk_ksu_db_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 5: KernelSU mount points */
    private fun checkKernelSUMountPoints(): DetectionResult {
        return try {
            val mounts = File("/proc/mounts").readText()
            val keywords = listOf("ksu", "kernelsu", "/data/adb/ksu")
            val found = keywords.filter { mounts.contains(it, ignoreCase = true) }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "ksu_mounts",
                    name = context.getString(R.string.chk_ksu_mounts_name),
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ksu_mounts_desc),
                    detailedReason = context.getString(R.string.chk_ksu_mounts_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_ksu_mounts_solution),
                    technicalDetail = "Keywords: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "ksu_mounts",
                    name = context.getString(R.string.chk_ksu_mounts_name_nd),
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ksu_mounts_desc_nd),
                    detailedReason = context.getString(R.string.chk_ksu_mounts_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "ksu_mounts",
                name = context.getString(R.string.chk_ksu_mounts_name_nd),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ksu_mounts_desc_error),
                detailedReason = context.getString(R.string.chk_ksu_mounts_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_ksu_mounts_solution_error)
            )
        }
    }

    /** Check 6: KernelSU running processes */
    private fun checkKernelSUProcesses(): DetectionResult {
        val ksuProcessNames = listOf("ksud", "ksu")
        val found = mutableListOf<String>()
        return try {
            val procDir = File("/proc")
            procDir.listFiles { _, name -> name.all { it.isDigit() } }?.forEach { pidDir ->
                try {
                    val cmdline = File(pidDir, "cmdline").readText()
                        .replace("\u0000", " ").trim()
                    ksuProcessNames.forEach { name ->
                        if (cmdline.contains(name, ignoreCase = true) && !found.contains(cmdline)) {
                            found.add(cmdline.take(50))
                        }
                    }
                } catch (_: Exception) {}
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "ksu_processes",
                    name = context.getString(R.string.chk_ksu_processes_name),
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ksu_processes_desc),
                    detailedReason = context.getString(R.string.chk_ksu_processes_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_ksu_processes_solution),
                    technicalDetail = "Processes: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "ksu_processes",
                    name = context.getString(R.string.chk_ksu_processes_name_nd),
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ksu_processes_desc_nd),
                    detailedReason = context.getString(R.string.chk_ksu_processes_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "ksu_processes",
                name = context.getString(R.string.chk_ksu_processes_name_nd),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ksu_processes_desc_error),
                detailedReason = context.getString(R.string.chk_ksu_processes_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_ksu_processes_solution_error)
            )
        }
    }

    /** Check 7: KernelSU custom syscall detection */
    private fun checkKernelSUSyscall(): DetectionResult {
        // KernelSU uses a custom syscall (number varies by implementation)
        // to communicate between userspace and kernel
        // We detect this by checking /proc/sys/kernel for ksu entries
        val ksuSysEntries = listOf(
            "/proc/sys/kernel/ksu",
            "/sys/kernel/ksu",
            "/sys/fs/selinux/enforce"
        )
        val found = ksuSysEntries.filter { File(it).exists() }

        // Check selinux status - KernelSU often sets permissive
        var selinuxStatus = "unknown"
        try {
            selinuxStatus = File("/sys/fs/selinux/enforce").readText().trim()
        } catch (_: Exception) {}

        val selinuxPermissive = selinuxStatus == "0"

        return if (found.contains("/sys/kernel/ksu") || found.contains("/proc/sys/kernel/ksu")) {
            DetectionResult(
                id = "ksu_syscall",
                name = context.getString(R.string.chk_ksu_syscall_name),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ksu_syscall_desc),
                detailedReason = context.getString(R.string.chk_ksu_syscall_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_ksu_syscall_solution),
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else if (selinuxPermissive) {
            DetectionResult(
                id = "ksu_syscall",
                name = context.getString(R.string.chk_ksu_syscall_name_selinux),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ksu_syscall_desc_selinux),
                detailedReason = context.getString(R.string.chk_ksu_syscall_reason_selinux),
                solution = context.getString(R.string.chk_ksu_syscall_solution_selinux),
                technicalDetail = "SELinux enforce: $selinuxStatus"
            )
        } else {
            DetectionResult(
                id = "ksu_syscall",
                name = context.getString(R.string.chk_ksu_syscall_name),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ksu_syscall_desc_nd),
                detailedReason = context.getString(R.string.chk_ksu_syscall_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "SELinux enforce: $selinuxStatus"
            )
        }
    }

    /** Check 8: KernelSU-related system properties */
    private fun checkKernelSUProps(): DetectionResult {
        val ksuProps = listOf(
            "ro.kernelsu.version",
            "kernelsu.version",
            "persist.kernelsu.enabled"
        )
        val found = mutableListOf<String>()
        ksuProps.forEach { key ->
            val value = getSystemProperty(key)
            if (value.isNotEmpty()) {
                found.add("$key=$value")
            }
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "ksu_props",
                name = context.getString(R.string.chk_ksu_props_name),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ksu_props_desc),
                detailedReason = context.getString(R.string.chk_ksu_props_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_ksu_props_solution),
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ksu_props",
                name = context.getString(R.string.chk_ksu_props_name),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ksu_props_desc_nd),
                detailedReason = context.getString(R.string.chk_ksu_props_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 9: KernelSU loop device detection.
     *
     * KernelSU LKM mode mounts its own filesystem image via a loop device. This loop
     * device is visible in /proc/mounts as a /dev/loop* device mounted at /data/adb
     * or similar KSU paths. On a clean device there should be no loop device mounts
     * at KSU-specific paths. The presence of such a mount is a strong KSU indicator.
     *
     * Chunqiu Detector item: "KnelsU loop device"
     */
    private fun checkKernelSULoopDevice(): DetectionResult {
        val ksuMountPaths = listOf(
            "/data/adb/ksu",
            "/data/adb/ksud",
            "/data/adb/modules"
        )
        val foundLoopMounts = mutableListOf<String>()
        return try {
            val mounts = File("/proc/self/mounts").readText()
            mounts.lines().forEach { line ->
                val parts = line.trim().split("\\s+".toRegex())
                if (parts.size < 3) return@forEach
                val device = parts[0]
                val mountPoint = parts[1]
                // A loop device (/dev/loop*) mounted at a KSU-related path is suspicious
                if (device.startsWith("/dev/loop") &&
                    ksuMountPaths.any { mountPoint.startsWith(it) }
                ) {
                    foundLoopMounts.add("$device→$mountPoint")
                }
            }
            // Also check for loop devices appearing in /proc/mounts with ksu in the path
            mounts.lines().forEach { line ->
                if (line.contains("/dev/loop") && line.contains("ksu", ignoreCase = true) &&
                    !foundLoopMounts.any { line.contains(it.substringBefore("→")) }
                ) {
                    foundLoopMounts.add(line.trim().take(80))
                }
            }
            if (foundLoopMounts.isNotEmpty()) {
                DetectionResult(
                    id = "ksu_loop_device",
                    name = context.getString(R.string.chk_ksu_loop_device_name),
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ksu_loop_device_desc),
                    detailedReason = context.getString(R.string.chk_ksu_loop_device_reason, foundLoopMounts.joinToString(", ")),
                    solution = context.getString(R.string.chk_ksu_loop_device_solution),
                    technicalDetail = "Loop mounts: ${foundLoopMounts.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "ksu_loop_device",
                    name = context.getString(R.string.chk_ksu_loop_device_name_nd),
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ksu_loop_device_desc_nd),
                    detailedReason = context.getString(R.string.chk_ksu_loop_device_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "ksu_loop_device",
                name = context.getString(R.string.chk_ksu_loop_device_name_nd),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ksu_loop_device_desc_nd),
                detailedReason = context.getString(R.string.chk_no_action_needed),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ---- Utilities ----

    private fun packageExists(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun getSystemProperty(key: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
        } catch (_: Exception) {
            ""
        }
    }
}
