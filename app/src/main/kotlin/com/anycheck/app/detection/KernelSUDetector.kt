package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
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
        checkKernelSUProps()
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
                name = "KernelSU Files Detected",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "KernelSU-specific files or directories found.",
                detailedReason = "The following KernelSU files were found: ${found.joinToString(", ")}. " +
                    "KernelSU is a kernel-based root solution. " +
                    "ksud is the KernelSU daemon and /data/adb/ksu is its working directory.",
                solution = "To remove KernelSU: Use KernelSU Manager → Uninstall, " +
                    "or flash a non-KernelSU kernel/stock boot image via fastboot.",
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ksu_files",
                name = "KernelSU Files",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No KernelSU-specific files detected.",
                detailedReason = "No known KernelSU file paths were found on this device.",
                solution = "No action required."
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
                name = "KernelSU Manager Detected",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "KernelSU Manager or related apps installed.",
                detailedReason = "Found KernelSU packages: ${found.joinToString(", ")}. " +
                    "The KernelSU Manager app is the management interface for KernelSU. " +
                    "Its presence confirms KernelSU is installed.",
                solution = "Use KernelSU Manager to uninstall, then flash a stock kernel.",
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ksu_packages",
                name = "KernelSU Manager Packages",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No KernelSU Manager packages found.",
                detailedReason = "No known KernelSU package names were installed.",
                solution = "No action required."
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
                    name = "KernelSU in Kernel Version",
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "KernelSU signature found in kernel version string.",
                    detailedReason = "The kernel version string contains KernelSU markers: ${allFound.joinToString(", ")}. " +
                        "KernelSU patches the kernel and embeds its version in the kernel string. " +
                        "Kernel: ${kernelVersion.take(100)}",
                    solution = "Flash a stock (non-KernelSU) kernel via fastboot or recovery.",
                    technicalDetail = "Kernel: ${kernelVersion.take(200)}"
                )
            } else {
                DetectionResult(
                    id = "ksu_kernel_version",
                    name = "KernelSU Kernel Version",
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No KernelSU signature in kernel version string.",
                    detailedReason = "The kernel version string does not contain KernelSU markers.",
                    solution = "No action required.",
                    technicalDetail = "Kernel: ${kernelVersion.take(100)}"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "ksu_kernel_version",
                name = "KernelSU Kernel Version",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not read kernel version.",
                detailedReason = "Failed to read /proc/version: ${e.message}",
                solution = "Ensure /proc/version is accessible."
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
                name = "KernelSU Database Found",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "KernelSU SQLite database detected.",
                detailedReason = "KernelSU uses a SQLite database to store allowed package UIDs and policy rules. " +
                    "Found at: ${found.joinToString(", ")}.",
                solution = "The database is removed when KernelSU is fully uninstalled.",
                technicalDetail = "DB paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ksu_db",
                name = "KernelSU Database",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "KernelSU database not found.",
                detailedReason = "No KernelSU database was found at known locations.",
                solution = "No action required."
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
                    name = "KernelSU Mount Points Detected",
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "KernelSU-related mount points found.",
                    detailedReason = "KernelSU uses OverlayFS to overlay module files. " +
                        "Keywords found in /proc/mounts: ${found.joinToString(", ")}.",
                    solution = "Mount points are managed by KernelSU. Removed upon uninstallation.",
                    technicalDetail = "Keywords: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "ksu_mounts",
                    name = "KernelSU Mount Points",
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No KernelSU mount points found.",
                    detailedReason = "No KernelSU-specific mount entries found.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "ksu_mounts",
                name = "KernelSU Mount Points",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read mount information.",
                detailedReason = "Failed to read /proc/mounts: ${e.message}",
                solution = "Ensure /proc/mounts is accessible."
            )
        }
    }

    /** Check 6: KernelSU running processes */
    private fun checkKernelSUProcesses(): DetectionResult {
        val ksuProcessNames = listOf("ksud", "ksu")
        val found = mutableListOf<String>()
        return try {
            val procDir = File("/proc")
            procDir.listFiles()?.forEach { pidDir ->
                if (pidDir.isDirectory && pidDir.name.all { it.isDigit() }) {
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
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "ksu_processes",
                    name = "KernelSU Processes Running",
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "KernelSU daemon processes are running.",
                    detailedReason = "Found processes: ${found.joinToString(", ")}. " +
                        "ksud is the KernelSU userspace daemon that handles su requests.",
                    solution = "Processes stop after KernelSU is removed and device rebooted.",
                    technicalDetail = "Processes: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "ksu_processes",
                    name = "KernelSU Processes",
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No KernelSU daemon processes found.",
                    detailedReason = "No KernelSU process names found in running process list.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "ksu_processes",
                name = "KernelSU Processes",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not enumerate processes.",
                detailedReason = "Process enumeration failed: ${e.message}",
                solution = "Ensure /proc is accessible."
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
                name = "KernelSU Kernel Interface",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "KernelSU kernel interface detected.",
                detailedReason = "KernelSU exposes a kernel interface at /sys/kernel/ksu or /proc/sys/kernel/ksu. " +
                    "This confirms KernelSU is compiled into the running kernel. " +
                    "Found: ${found.joinToString(", ")}.",
                solution = "Flash a stock kernel without KernelSU to remove this interface.",
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else if (selinuxPermissive) {
            DetectionResult(
                id = "ksu_syscall",
                name = "SELinux Permissive Mode",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "SELinux is in permissive mode (potential KernelSU indicator).",
                detailedReason = "SELinux enforce status is 0 (permissive). " +
                    "KernelSU and other root solutions often set SELinux to permissive mode " +
                    "to allow unrestricted root access. This significantly reduces device security.",
                solution = "Set SELinux to enforcing mode: `setenforce 1`. " +
                    "This setting persists only until reboot unless KernelSU/Magisk policies override it.",
                technicalDetail = "SELinux enforce: $selinuxStatus"
            )
        } else {
            DetectionResult(
                id = "ksu_syscall",
                name = "KernelSU Kernel Interface",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No KernelSU kernel interface found.",
                detailedReason = "No KernelSU-specific kernel interfaces were detected.",
                solution = "No action required.",
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
                name = "KernelSU System Properties",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "KernelSU-specific system properties found.",
                detailedReason = "The following KernelSU properties were found: ${found.joinToString(", ")}. " +
                    "These properties are set by KernelSU and confirm its presence.",
                solution = "These properties are removed when KernelSU is uninstalled.",
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ksu_props",
                name = "KernelSU System Properties",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No KernelSU system properties found.",
                detailedReason = "No KernelSU-specific system properties were detected.",
                solution = "No action required."
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
