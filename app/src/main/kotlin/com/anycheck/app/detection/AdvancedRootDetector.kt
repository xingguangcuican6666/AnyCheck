package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Advanced root detection checks: system integrity, ADB/debug status, Frida, Riru,
 * custom recovery, emulator, injected libraries, kernel modules, and more.
 */
class AdvancedRootDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkSuCommandExecution(),
        checkReadWriteSystemPartition(),
        checkBootloaderUnlocked(),
        checkDmVerityDisabled(),
        checkDangerousProperties(),
        checkDeveloperOptions(),
        checkUsbDebugging(),
        checkFridaProcess(),
        checkFridaTcpPort(),
        checkFridaFiles(),
        checkRiruFramework(),
        checkTWRPRecovery(),
        checkEmulatorDetection(),
        checkInjectedLibraries(),
        checkZygiskCompanionSocket(),
        checkMagiskModuleCount(),
        checkDebuggerAttached(),
        checkRootCloakingApps(),
        checkKernelModules()
    )

    /** Check 1: Execute `which su` to discover su in PATH */
    private fun checkSuCommandExecution(): DetectionResult {
        var suPath = ""
        try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            suPath = BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
            process.waitFor()
        } catch (_: Exception) {}

        return if (suPath.isNotEmpty()) {
            DetectionResult(
                id = "su_command",
                name = "SU Found via PATH",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "su binary found in PATH via 'which su'.",
                detailedReason = "Executing 'which su' returned '$suPath'. " +
                    "The su binary is installed and accessible from the shell PATH, " +
                    "confirming root access is available to shell commands.",
                solution = "Remove the su binary from the reported path.",
                technicalDetail = "which su → $suPath"
            )
        } else {
            DetectionResult(
                id = "su_command",
                name = "SU via PATH",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "su binary not found via PATH lookup.",
                detailedReason = "The 'which su' command returned no result.",
                solution = "No action required."
            )
        }
    }

    /** Check 2: System / vendor partition mounted read-write */
    private fun checkReadWriteSystemPartition(): DetectionResult {
        return try {
            val mounts = File("/proc/mounts").readText()
            val rwMounts = mounts.lines().filter { line ->
                val parts = line.split(" ")
                if (parts.size < 4) return@filter false
                val mountPoint = parts[1]
                val flags = parts[3].split(",")
                (mountPoint == "/system" || mountPoint == "/vendor" || mountPoint == "/product" ||
                    mountPoint == "/system_ext") && flags.contains("rw")
            }
            if (rwMounts.isNotEmpty()) {
                val points = rwMounts.map { it.split(" ").getOrElse(1) { "?" } }
                DetectionResult(
                    id = "rw_system",
                    name = "System Partition Mounted R/W",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "System partition is mounted read-write.",
                    detailedReason = "Partitions ${points.joinToString(", ")} are mounted read-write. " +
                        "Normally system partitions are read-only for security. " +
                        "A read-write system mount means system files can be modified at runtime.",
                    solution = "Remount as read-only: 'mount -o remount,ro /system'",
                    technicalDetail = rwMounts.joinToString("\n")
                )
            } else {
                DetectionResult(
                    id = "rw_system",
                    name = "System Partition Mount",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "System partitions appear to be read-only.",
                    detailedReason = "No read-write system partition mounts were found.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "rw_system",
                name = "System Partition Mount",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not read /proc/mounts.",
                detailedReason = "Failed: ${e.message}",
                solution = "Ensure /proc/mounts is accessible."
            )
        }
    }

    /** Check 3: Bootloader unlock state */
    private fun checkBootloaderUnlocked(): DetectionResult {
        val verifiedBootState = getSystemProperty("ro.boot.verifiedbootstate")
        val flashLocked = getSystemProperty("ro.boot.flash.locked")
        val vbmetaState = getSystemProperty("ro.boot.vbmeta.device_state")

        val unlocked = verifiedBootState == "orange" ||
            verifiedBootState == "yellow" ||
            flashLocked == "0" ||
            vbmetaState == "unlocked"

        val indicators = mutableListOf<String>()
        if (verifiedBootState.isNotEmpty()) indicators.add("ro.boot.verifiedbootstate=$verifiedBootState")
        if (flashLocked.isNotEmpty()) indicators.add("ro.boot.flash.locked=$flashLocked")
        if (vbmetaState.isNotEmpty()) indicators.add("ro.boot.vbmeta.device_state=$vbmetaState")

        return if (unlocked) {
            DetectionResult(
                id = "bootloader_unlocked",
                name = "Bootloader Unlocked",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Device bootloader is unlocked.",
                detailedReason = "Bootloader unlock indicators: ${indicators.joinToString(", ")}. " +
                    "An unlocked bootloader allows flashing unsigned boot images, custom kernels " +
                    "(required for KernelSU/APatch), and custom recoveries (TWRP). " +
                    "Verified Boot is disabled, so OS integrity is not guaranteed.",
                solution = "Lock the bootloader via 'fastboot flashing lock' after restoring stock firmware. " +
                    "Warning: locking with custom firmware may brick the device.",
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "bootloader_unlocked",
                name = "Bootloader State",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Bootloader appears to be locked.",
                detailedReason = "Boot state indicators suggest a locked bootloader: ${indicators.joinToString(", ")}.",
                solution = "No action required.",
                technicalDetail = indicators.joinToString("; ")
            )
        }
    }

    /** Check 4: dm-verity / Verified Boot disabled */
    private fun checkDmVerityDisabled(): DetectionResult {
        val verityMode = getSystemProperty("ro.boot.veritymode")
        val partitionVerified = getSystemProperty("partition.system.verified")

        val disabled = verityMode.contains("disabled", ignoreCase = true) ||
            verityMode.contains("logging", ignoreCase = true) ||
            partitionVerified == "0"

        val indicators = mutableListOf<String>()
        if (verityMode.isNotEmpty()) indicators.add("ro.boot.veritymode=$verityMode")
        if (partitionVerified.isNotEmpty()) indicators.add("partition.system.verified=$partitionVerified")

        return if (disabled) {
            DetectionResult(
                id = "dm_verity",
                name = "dm-verity Disabled",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "dm-verity (Verified Boot) appears to be disabled.",
                detailedReason = "dm-verity protects system partition integrity by verifying each block on read. " +
                    "When disabled: ${indicators.joinToString(", ")}. " +
                    "System files can be modified without Verified Boot detecting the change.",
                solution = "Re-enable dm-verity by restoring a stock boot image and locking the bootloader.",
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "dm_verity",
                name = "dm-verity Status",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "dm-verity appears to be enabled.",
                detailedReason = "No dm-verity disable indicators found.",
                solution = "No action required.",
                technicalDetail = indicators.joinToString("; ")
            )
        }
    }

    /** Check 5: Dangerous system properties indicating debug / root access */
    private fun checkDangerousProperties(): DetectionResult {
        val dangerousProps = mapOf(
            "ro.adb.secure" to listOf("0"),
            "service.adb.root" to listOf("1"),
            "ro.allow.mock.location" to listOf("1"),
            "ro.debuggable" to listOf("1"),
            "ro.secure" to listOf("0"),
            "ro.build.type" to listOf("userdebug", "eng")
        )
        val found = mutableListOf<String>()
        dangerousProps.forEach { (key, dangerousValues) ->
            val value = getSystemProperty(key)
            if (value.isNotEmpty() && dangerousValues.any { value == it }) {
                found.add("$key=$value")
            }
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "dangerous_props",
                name = "Dangerous Properties Detected",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Dangerous system properties indicate debug or root access.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "ro.adb.secure=0 means ADB shell is not secured. " +
                    "service.adb.root=1 means the ADB daemon runs as root. " +
                    "ro.debuggable=1 enables app debugging for all apps. " +
                    "ro.build.type=userdebug/eng indicates a development build with relaxed security.",
                solution = "Use a production (user) build to restore secure property defaults.",
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "dangerous_props",
                name = "System Property Security",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No dangerous system properties found.",
                detailedReason = "Checked properties appear to have secure values.",
                solution = "No action required."
            )
        }
    }

    /** Check 6: Developer Options enabled */
    private fun checkDeveloperOptions(): DetectionResult {
        return try {
            val devEnabled = Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
            )
            if (devEnabled == 1) {
                DetectionResult(
                    id = "developer_options",
                    name = "Developer Options Enabled",
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "Android Developer Options is enabled.",
                    detailedReason = "Developer Options grants access to advanced settings including " +
                        "USB debugging, OEM unlock, process inspection, and GPU rendering tools. " +
                        "While not root itself, it is a prerequisite for most rooting methods.",
                    solution = "Disable via Settings → System → Developer Options → toggle off.",
                    technicalDetail = "DEVELOPMENT_SETTINGS_ENABLED=1"
                )
            } else {
                DetectionResult(
                    id = "developer_options",
                    name = "Developer Options",
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "Developer Options is disabled.",
                    detailedReason = "DEVELOPMENT_SETTINGS_ENABLED is 0.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "developer_options",
                name = "Developer Options",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.MEDIUM,
                description = "Could not read Developer Options status.",
                detailedReason = "Settings query failed: ${e.message}",
                solution = "Check manually in Settings → System → Developer Options."
            )
        }
    }

    /** Check 7: USB debugging (ADB) enabled */
    private fun checkUsbDebugging(): DetectionResult {
        return try {
            val adbEnabled = Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.ADB_ENABLED, 0
            )
            if (adbEnabled == 1) {
                DetectionResult(
                    id = "usb_debugging",
                    name = "USB Debugging Enabled",
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "ADB (USB debugging) is currently enabled.",
                    detailedReason = "USB debugging allows a connected computer to execute adb commands, " +
                        "install/remove apps, extract data, and (on debug builds) obtain a root shell. " +
                        "It is commonly used as part of the rooting process.",
                    solution = "Disable via Settings → Developer Options → USB Debugging → toggle off.",
                    technicalDetail = "Settings.Global.ADB_ENABLED=1"
                )
            } else {
                DetectionResult(
                    id = "usb_debugging",
                    name = "USB Debugging",
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "USB debugging (ADB) is disabled.",
                    detailedReason = "Settings.Global.ADB_ENABLED is 0.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "usb_debugging",
                name = "USB Debugging",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read USB debugging status.",
                detailedReason = "Settings query failed: ${e.message}",
                solution = "Check manually in Settings → Developer Options."
            )
        }
    }

    /** Check 8: Frida dynamic instrumentation server running */
    private fun checkFridaProcess(): DetectionResult {
        val fridaProcessNames = listOf("frida-server", "frida-gadget", "frida-helper", "frida")
        val found = mutableListOf<String>()
        return try {
            val procDir = File("/proc")
            procDir.listFiles()?.forEach { pidDir ->
                if (pidDir.isDirectory && pidDir.name.all { it.isDigit() }) {
                    try {
                        val cmdline = File(pidDir, "cmdline").readText()
                            .replace("\u0000", " ").trim()
                        fridaProcessNames.forEach { name ->
                            if (cmdline.contains(name, ignoreCase = true) && !found.contains(cmdline)) {
                                found.add(cmdline.take(60))
                            }
                        }
                    } catch (_: Exception) {}
                }
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "frida_process",
                    name = "Frida Server Running",
                    category = DetectionCategory.FRIDA,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "Frida dynamic instrumentation server is running.",
                    detailedReason = "Frida is a reverse engineering toolkit used for runtime hooking, " +
                        "tracing, and app tampering. Found processes: ${found.joinToString(", ")}. " +
                        "frida-server enables remote injection and patching of running processes.",
                    solution = "Kill the frida-server process: 'kill \$(pgrep frida-server)'",
                    technicalDetail = "Processes: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "frida_process",
                    name = "Frida Process",
                    category = DetectionCategory.FRIDA,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No Frida server processes found.",
                    detailedReason = "No frida-server or related processes are running.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "frida_process",
                name = "Frida Process",
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not enumerate running processes.",
                detailedReason = "Process enumeration failed: ${e.message}",
                solution = "Ensure /proc is accessible."
            )
        }
    }

    /** Check 9: Frida default TCP port 27042 / 27043 listening */
    private fun checkFridaTcpPort(): DetectionResult {
        val fridaPorts = setOf(27042, 27043)
        val openPorts = mutableListOf<Int>()

        listOf("/proc/net/tcp", "/proc/net/tcp6").forEach { tcpFile ->
            try {
                File(tcpFile).readLines().drop(1).forEach { line ->
                    val parts = line.trim().split("\\s+".toRegex())
                    if (parts.size >= 4 && parts[3] == "0A") { // 0A = LISTEN
                        val portHex = parts[1].split(":").lastOrNull() ?: return@forEach
                        try {
                            val port = portHex.toInt(16)
                            if (port in fridaPorts && port !in openPorts) openPorts.add(port)
                        } catch (_: NumberFormatException) {}
                    }
                }
            } catch (_: Exception) {}
        }

        return if (openPorts.isNotEmpty()) {
            DetectionResult(
                id = "frida_port",
                name = "Frida Port Open",
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Frida server default port(s) are listening.",
                detailedReason = "Ports ${openPorts.joinToString(", ")} are in LISTEN state. " +
                    "Port 27042 is the Frida server default. " +
                    "An open Frida port confirms the server is active and accepting connections.",
                solution = "Kill the Frida server process.",
                technicalDetail = "Listening ports: ${openPorts.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "frida_port",
                name = "Frida Port",
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Frida ports detected as listening.",
                detailedReason = "Ports 27042/27043 are not in LISTEN state.",
                solution = "No action required."
            )
        }
    }

    /** Check 10: Frida server binary files on disk */
    private fun checkFridaFiles(): DetectionResult {
        val fridaFiles = listOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/frida",
            "/data/local/tmp/re.frida.server",
            "/sdcard/frida-server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server",
            "/data/local/frida-server"
        )
        val found = fridaFiles.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "frida_files",
                name = "Frida Server Files Found",
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Frida server binary found on the filesystem.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "Frida server binaries are typically placed in /data/local/tmp before execution. " +
                    "Their presence indicates active or recent reverse engineering activity.",
                solution = "Delete the binary: 'rm /data/local/tmp/frida-server'",
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "frida_files",
                name = "Frida Server Files",
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No Frida server files found.",
                detailedReason = "No Frida server binaries found at common locations.",
                solution = "No action required."
            )
        }
    }

    /** Check 11: Riru Zygote injection framework */
    private fun checkRiruFramework(): DetectionResult {
        val riruFiles = listOf(
            "/data/adb/riru",
            "/data/adb/riru/lib",
            "/data/adb/modules/riru-core",
            "/system/lib/libmemtrack_real.so",
            "/system/lib64/libmemtrack_real.so",
            "/data/misc/riru"
        )
        val foundFiles = riruFiles.filter { File(it).exists() }

        return if (foundFiles.isNotEmpty()) {
            DetectionResult(
                id = "riru",
                name = "Riru Framework Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Riru Zygote injection framework detected.",
                detailedReason = "Riru injects code into the Zygote process to enable system-wide hooks. " +
                    "It is a predecessor to Zygisk. Found: ${foundFiles.joinToString(", ")}. " +
                    "libmemtrack_real.so is the backup of the original libmemtrack that Riru replaces.",
                solution = "Remove Riru via the Magisk/KernelSU module manager.",
                technicalDetail = "Files: ${foundFiles.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "riru",
                name = "Riru Framework",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Riru framework not detected.",
                detailedReason = "No Riru files were found.",
                solution = "No action required."
            )
        }
    }

    /** Check 12: TWRP / custom recovery artifacts */
    private fun checkTWRPRecovery(): DetectionResult {
        val recoveryFiles = listOf(
            "/cache/recovery/last_install",
            "/cache/recovery/log",
            "/cache/recovery/command",
            "/tmp/recovery.log",
            "/sdcard/TWRP",
            "/external_sd/TWRP"
        )
        val twrpPackages = listOf(
            "me.twrp.twrpapp",
            "com.teamwin.twrpapp"
        )
        val foundFiles = recoveryFiles.filter { File(it).exists() }
        val foundPkgs = twrpPackages.filter { packageExists(it) }

        return if (foundFiles.isNotEmpty() || foundPkgs.isNotEmpty()) {
            val indicators = mutableListOf<String>()
            if (foundFiles.isNotEmpty()) indicators.add("Files: ${foundFiles.joinToString(", ")}")
            if (foundPkgs.isNotEmpty()) indicators.add("Packages: ${foundPkgs.joinToString(", ")}")
            DetectionResult(
                id = "twrp_recovery",
                name = "Custom Recovery (TWRP) Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "TWRP or custom recovery artifacts detected.",
                detailedReason = "TWRP allows flashing custom ROMs and root packages from recovery mode. " +
                    "Evidence: ${indicators.joinToString("; ")}.",
                solution = "Flash stock recovery via fastboot: 'fastboot flash recovery stock_recovery.img'",
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "twrp_recovery",
                name = "Custom Recovery",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No TWRP or custom recovery artifacts found.",
                detailedReason = "No known TWRP files or packages were detected.",
                solution = "No action required."
            )
        }
    }

    /** Check 13: Emulator / virtual machine detection */
    private fun checkEmulatorDetection(): DetectionResult {
        val indicators = mutableListOf<String>()

        val hardware = Build.HARDWARE.lowercase()
        val product = Build.PRODUCT.lowercase()
        val manufacturer = Build.MANUFACTURER.lowercase()
        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val brand = Build.BRAND.lowercase()

        val emulatorHardware = listOf("goldfish", "ranchu", "vbox86", "vbox")
        val emulatorProducts = listOf("sdk_gphone", "sdk_gphone_x86", "vbox86", "emulator", "genymotion")

        emulatorHardware.forEach { h -> if (hardware.contains(h)) indicators.add("hardware=$hardware") }
        emulatorProducts.forEach { p -> if (product.contains(p) && indicators.none { it.startsWith("product=") }) indicators.add("product=$product") }

        if (manufacturer == "genymotion") indicators.add("manufacturer=genymotion")
        if (brand == "generic" || brand.startsWith("unknown")) indicators.add("brand=$brand")
        if (fingerprint.contains("generic") || fingerprint.contains("sdk_gphone")) indicators.add("fingerprint has generic/sdk_gphone")
        if (model.contains("sdk") || model.contains("emulator")) indicators.add("model=$model")

        val emulatorFiles = listOf("/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/vbox_pipe", "/dev/hvc0")
        val foundFiles = emulatorFiles.filter { File(it).exists() }
        if (foundFiles.isNotEmpty()) indicators.add("emulator devices: ${foundFiles.joinToString(", ")}")

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "emulator",
                name = "Emulator/VM Detected",
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Device appears to be an emulator or virtual machine.",
                detailedReason = "Emulator indicators: ${indicators.joinToString("; ")}. " +
                    "Emulators often have relaxed security settings and can more easily simulate rooting.",
                solution = "Use a physical device for production/security-sensitive use cases.",
                technicalDetail = "Indicators: ${indicators.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "emulator",
                name = "Emulator Detection",
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Device does not appear to be an emulator.",
                detailedReason = "No emulator indicators were found.",
                solution = "No action required."
            )
        }
    }

    /** Check 14: Root/hook framework libraries injected into this process */
    private fun checkInjectedLibraries(): DetectionResult {
        val suspiciousPatterns = listOf(
            "magisk", "zygisk", "ksu", "kernelsu", "frida",
            "xposed", "lsposed", "edxposed", "riru", "inject", "hook"
        )
        val found = mutableListOf<String>()
        return try {
            val maps = File("/proc/self/maps").readText()
            maps.lines().forEach { line ->
                suspiciousPatterns.forEach { pattern ->
                    if (line.contains(pattern, ignoreCase = true) && line.contains(".so") &&
                        found.none { it.contains(pattern, ignoreCase = true) }
                    ) {
                        val path = line.trim().split("\\s+".toRegex()).lastOrNull()?.trim() ?: ""
                        if (path.isNotEmpty()) found.add(path.take(80))
                    }
                }
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "injected_libs",
                    name = "Injected Libraries Detected",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "Root/hook framework libraries are injected into this process.",
                    detailedReason = "Suspicious libraries mapped in /proc/self/maps: ${found.joinToString(", ")}. " +
                        "Library injection is used by Zygisk, Riru, LSPosed, and Frida to hook app code at runtime.",
                    solution = "Remove the root framework to prevent library injection.",
                    technicalDetail = "Mapped libs: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "injected_libs",
                    name = "Injected Libraries",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No suspicious libraries injected into this process.",
                    detailedReason = "No root/hook framework libraries found in /proc/self/maps.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "injected_libs",
                name = "Injected Libraries",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not read process memory maps.",
                detailedReason = "Failed to read /proc/self/maps: ${e.message}",
                solution = "Ensure /proc/self/maps is accessible."
            )
        }
    }

    /** Check 15: Zygisk companion process socket in /proc/net/unix */
    private fun checkZygiskCompanionSocket(): DetectionResult {
        val zygiskSockets = listOf("@zygisk", "zygisk_companion", "@zygisk_zygote", "zygisk_daemon")
        return try {
            val content = File("/proc/net/unix").readText()
            val found = zygiskSockets.filter { content.contains(it, ignoreCase = true) }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "zygisk_socket",
                    name = "Zygisk Companion Socket",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Zygisk companion process socket detected.",
                    detailedReason = "Zygisk uses a companion process in Zygote that communicates via Unix sockets. " +
                        "Sockets found: ${found.joinToString(", ")}. " +
                        "This confirms Zygisk is actively running and injecting into app processes.",
                    solution = "Disable Zygisk in Magisk settings or uninstall Magisk.",
                    technicalDetail = "Sockets: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "zygisk_socket",
                    name = "Zygisk Companion Socket",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No Zygisk companion socket found.",
                    detailedReason = "No Zygisk socket names found in /proc/net/unix.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "zygisk_socket",
                name = "Zygisk Companion Socket",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read /proc/net/unix.",
                detailedReason = "Failed: ${e.message}",
                solution = "Ensure /proc/net/unix is accessible."
            )
        }
    }

    /** Check 16: Count installed Magisk modules */
    private fun checkMagiskModuleCount(): DetectionResult {
        val modulesDir = File("/data/adb/modules")
        return if (modulesDir.exists() && modulesDir.isDirectory) {
            val modules = modulesDir.listFiles()?.filter { it.isDirectory } ?: emptyList()
            if (modules.isNotEmpty()) {
                val nameList = modules.take(10).map { it.name }
                DetectionResult(
                    id = "magisk_module_count",
                    name = "Magisk Modules Installed",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "${modules.size} Magisk module(s) installed.",
                    detailedReason = "Found ${modules.size} module(s) in /data/adb/modules: " +
                        "${nameList.joinToString(", ")}${if (modules.size > 10) "…" else ""}. " +
                        "Magisk modules can modify system files, inject libraries, and alter app behaviour.",
                    solution = "Review installed modules in Magisk Manager and remove untrusted ones.",
                    technicalDetail = "Modules: ${modules.map { it.name }.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "magisk_module_count",
                    name = "Magisk Modules",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "No Magisk modules installed.",
                    detailedReason = "/data/adb/modules exists but contains no module directories.",
                    solution = "No action required."
                )
            }
        } else {
            DetectionResult(
                id = "magisk_module_count",
                name = "Magisk Modules",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Magisk modules directory not found.",
                detailedReason = "/data/adb/modules does not exist.",
                solution = "No action required."
            )
        }
    }

    /** Check 17: TracerPid in /proc/self/status (debugger / ptrace attach) */
    private fun checkDebuggerAttached(): DetectionResult {
        return try {
            val status = File("/proc/self/status").readText()
            val tracerPidLine = status.lines().firstOrNull { it.startsWith("TracerPid:") }
            val tracerPid = tracerPidLine?.substringAfter("TracerPid:")?.trim()?.toIntOrNull() ?: 0
            if (tracerPid != 0) {
                DetectionResult(
                    id = "debugger_attached",
                    name = "Debugger Attached",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "A debugger or tracer is attached to this process.",
                    detailedReason = "TracerPid=$tracerPid in /proc/self/status. " +
                        "A non-zero TracerPid means another process is using ptrace on this app. " +
                        "This is used by debuggers (e.g. Android Studio, GDB) and also by some " +
                        "tampering tools (e.g. Frida gadget, Objection).",
                    solution = "Disconnect the debugger. If in production, this indicates tampering.",
                    technicalDetail = "TracerPid=$tracerPid"
                )
            } else {
                DetectionResult(
                    id = "debugger_attached",
                    name = "Debugger Attached",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No debugger attached to this process.",
                    detailedReason = "TracerPid=0 — no process is tracing this app.",
                    solution = "No action required.",
                    technicalDetail = "TracerPid=0"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "debugger_attached",
                name = "Debugger Attached",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read /proc/self/status.",
                detailedReason = "Status read failed: ${e.message}",
                solution = "Ensure /proc/self/status is accessible."
            )
        }
    }

    /** Check 18: Root-cloaking / SafetyNet bypass apps */
    private fun checkRootCloakingApps(): DetectionResult {
        val cloakingApps = listOf(
            "com.devadvance.rootcloak",            // RootCloak
            "com.devadvance.rootcloakplus",        // RootCloak Plus
            "de.robv.android.xposed.installer",    // Xposed (enables cloaking modules)
            "eu.chainfire.xposed.nofing",          // NoFingerprintService
            "com.github.uberspot.antisnitch",       // Anti-Snitch
            "io.github.vvb2060.magisk",            // Shamiko (detection bypass Magisk)
            "com.offsec.nhsystem",                 // NetHunter (security testing)
            "com.zachspong.temprootremovejb",      // TempRoot remover
            "com.amphoras.hidemyroot",             // HideMyRoot
            "com.formyhm.hideroot",                // HideRoot
            "io.github.huskydg.magisk",            // Magisk Delta (often used with cloaking)
            "me.bmax.apatch.plugin"                // APatch plugin
        )
        val found = cloakingApps.filter { packageExists(it) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "root_cloaking",
                name = "Root-Cloaking Apps Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Apps designed to hide or bypass root detection found.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "These apps attempt to conceal root indicators from other apps, " +
                    "bypassing SafetyNet, Play Integrity, and in-app root checks.",
                solution = "Uninstall root-cloaking apps via Settings → Apps.",
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "root_cloaking",
                name = "Root-Cloaking Apps",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No root-cloaking apps detected.",
                detailedReason = "No known root-cloaking packages were found.",
                solution = "No action required."
            )
        }
    }

    /** Check 19: KernelSU / APatch kernel module in /proc/modules */
    private fun checkKernelModules(): DetectionResult {
        return try {
            val modules = File("/proc/modules").readText()
            val suspiciousModules = listOf("ksu", "kernelsu", "apatch", "apd")
            val found = suspiciousModules.filter { modules.contains(it, ignoreCase = true) }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "kernel_modules",
                    name = "Root Kernel Module Loaded",
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "KernelSU or APatch kernel module found in /proc/modules.",
                    detailedReason = "Kernel module strings found: ${found.joinToString(", ")}. " +
                        "KernelSU on GKI kernels may load as a kernel module. " +
                        "Finding ksu/kernelsu in /proc/modules confirms kernel-level root.",
                    solution = "Flash a stock kernel without the KernelSU or APatch module.",
                    technicalDetail = "Modules: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "kernel_modules",
                    name = "Root Kernel Modules",
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No root-related kernel modules found.",
                    detailedReason = "No KernelSU or APatch kernel module strings were found in /proc/modules.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "kernel_modules",
                name = "Root Kernel Modules",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not read /proc/modules.",
                detailedReason = "Failed: ${e.message}",
                solution = "Ensure /proc/modules is accessible."
            )
        }
    }

    // ---- Utilities ----

    private fun getSystemProperty(key: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
        } catch (_: Exception) {
            ""
        }
    }

    private fun packageExists(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }
}
