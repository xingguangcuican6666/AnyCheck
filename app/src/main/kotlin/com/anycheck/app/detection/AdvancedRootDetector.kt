package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.anycheck.app.R
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
                name = context.getString(R.string.chk_adv_su_path_name),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_su_path_desc),
                detailedReason = context.getString(R.string.chk_adv_su_path_reason, suPath),
                solution = context.getString(R.string.chk_adv_su_path_solution),
                technicalDetail = "which su → $suPath"
            )
        } else {
            DetectionResult(
                id = "su_command",
                name = context.getString(R.string.chk_adv_su_path_name_nd),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_su_path_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_su_path_reason_nd),
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
                    name = context.getString(R.string.chk_adv_rw_sys_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_adv_rw_sys_desc),
                    detailedReason = context.getString(R.string.chk_adv_rw_sys_reason, points.joinToString(", ")),
                    solution = context.getString(R.string.chk_adv_rw_sys_solution),
                    technicalDetail = rwMounts.joinToString("\n")
                )
            } else {
                DetectionResult(
                    id = "rw_system",
                    name = "System Partition Mount",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_adv_rw_sys_desc_nd),
                    detailedReason = context.getString(R.string.chk_adv_rw_sys_reason_nd),
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "rw_system",
                name = "System Partition Mount",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_rw_sys_desc_error),
                detailedReason = "Failed: ${e.message}",
                solution = context.getString(R.string.chk_adv_rw_sys_solution_error)
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
                name = context.getString(R.string.chk_adv_bootloader_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_bootloader_desc),
                detailedReason = context.getString(R.string.chk_adv_bootloader_reason, indicators.joinToString(", ")),
                solution = context.getString(R.string.chk_adv_bootloader_solution),
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "bootloader_unlocked",
                name = context.getString(R.string.chk_adv_bootloader_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_bootloader_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_bootloader_reason_nd, indicators.joinToString(", ")),
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
                name = context.getString(R.string.chk_adv_dm_verity_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_dm_verity_desc),
                detailedReason = context.getString(R.string.chk_adv_dm_verity_reason, indicators.joinToString(", ")),
                solution = context.getString(R.string.chk_adv_dm_verity_solution),
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "dm_verity",
                name = context.getString(R.string.chk_adv_dm_verity_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_dm_verity_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_dm_verity_reason_nd),
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
                name = context.getString(R.string.chk_adv_dang_props_name),
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_dang_props_desc),
                detailedReason = context.getString(R.string.chk_adv_dang_props_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_adv_dang_props_solution),
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "dangerous_props",
                name = context.getString(R.string.chk_adv_dang_props_name_nd),
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_dang_props_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_dang_props_reason_nd),
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
                    name = context.getString(R.string.chk_adv_dev_opts_name),
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_adv_dev_opts_desc),
                    detailedReason = context.getString(R.string.chk_adv_dev_opts_reason),
                    solution = context.getString(R.string.chk_adv_dev_opts_solution),
                    technicalDetail = "DEVELOPMENT_SETTINGS_ENABLED=1"
                )
            } else {
                DetectionResult(
                    id = "developer_options",
                    name = "Developer Options",
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_adv_dev_opts_desc_nd),
                    detailedReason = context.getString(R.string.chk_adv_dev_opts_reason_nd),
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "developer_options",
                name = "Developer Options",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_adv_dev_opts_desc_error),
                detailedReason = "Settings query failed: ${e.message}",
                solution = context.getString(R.string.chk_adv_dev_opts_solution_error)
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
                    name = context.getString(R.string.chk_adv_adb_name),
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_adv_adb_desc),
                    detailedReason = context.getString(R.string.chk_adv_adb_reason),
                    solution = context.getString(R.string.chk_adv_adb_solution),
                    technicalDetail = "Settings.Global.ADB_ENABLED=1"
                )
            } else {
                DetectionResult(
                    id = "usb_debugging",
                    name = "USB Debugging",
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_adv_adb_desc_nd),
                    detailedReason = context.getString(R.string.chk_adv_adb_reason_nd),
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "usb_debugging",
                name = "USB Debugging",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_adb_desc_error),
                detailedReason = "Settings query failed: ${e.message}",
                solution = context.getString(R.string.chk_adv_adb_solution_error)
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
                    name = context.getString(R.string.chk_adv_frida_proc_name),
                    category = DetectionCategory.FRIDA,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_adv_frida_proc_desc),
                    detailedReason = context.getString(R.string.chk_adv_frida_proc_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_adv_frida_proc_solution),
                    technicalDetail = "Processes: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "frida_process",
                    name = "Frida Process",
                    category = DetectionCategory.FRIDA,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_adv_frida_proc_desc_nd),
                    detailedReason = context.getString(R.string.chk_adv_frida_proc_reason_nd),
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "frida_process",
                name = "Frida Process",
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_frida_proc_desc_error),
                detailedReason = "Process enumeration failed: ${e.message}",
                solution = context.getString(R.string.chk_adv_frida_proc_solution_error)
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
                name = context.getString(R.string.chk_adv_frida_port_name),
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_frida_port_desc),
                detailedReason = context.getString(R.string.chk_adv_frida_port_reason, openPorts.joinToString(", ")),
                solution = context.getString(R.string.chk_adv_frida_port_solution),
                technicalDetail = "Listening ports: ${openPorts.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "frida_port",
                name = context.getString(R.string.chk_adv_frida_port_name_nd),
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_frida_port_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_frida_port_reason_nd),
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
                name = context.getString(R.string.chk_adv_frida_files_name),
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_frida_files_desc),
                detailedReason = context.getString(R.string.chk_adv_frida_files_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_adv_frida_files_solution),
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "frida_files",
                name = context.getString(R.string.chk_adv_frida_files_name_nd),
                category = DetectionCategory.FRIDA,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_frida_files_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_frida_files_reason_nd),
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
                name = context.getString(R.string.chk_adv_riru_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_riru_desc),
                detailedReason = context.getString(R.string.chk_adv_riru_reason, foundFiles.joinToString(", ")),
                solution = context.getString(R.string.chk_adv_riru_solution),
                technicalDetail = "Files: ${foundFiles.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "riru",
                name = context.getString(R.string.chk_adv_riru_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_riru_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_riru_reason_nd),
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
                name = context.getString(R.string.chk_adv_twrp_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_twrp_desc),
                detailedReason = context.getString(R.string.chk_adv_twrp_reason, indicators.joinToString("; ")),
                solution = context.getString(R.string.chk_adv_twrp_solution),
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "twrp_recovery",
                name = context.getString(R.string.chk_adv_twrp_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_twrp_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_twrp_reason_nd),
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
                name = context.getString(R.string.chk_adv_emulator_name),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_adv_emulator_desc),
                detailedReason = context.getString(R.string.chk_adv_emulator_reason, indicators.joinToString("; ")),
                solution = context.getString(R.string.chk_adv_emulator_solution),
                technicalDetail = "Indicators: ${indicators.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "emulator",
                name = context.getString(R.string.chk_adv_emulator_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_adv_emulator_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_emulator_reason_nd),
                solution = "No action required."
            )
        }
    }

    /** Check 14: Root/hook framework libraries injected into this process */
    private fun checkInjectedLibraries(): DetectionResult {
        // Check the FILENAME (basename) only — not the full path — to avoid false positives
        // from Magisk mirror paths like /sbin/.magisk/mirror/system/lib64/libfoo.so
        // where "magisk" appears only in the mount-point prefix, not the library name itself.
        val suspiciousFilenamePatterns = listOf(
            "magisk", "zygisk", "frida", "xposed", "lsposed", "edxposed", "riru"
        )
        // For generic patterns (inject/hook) only flag libraries outside trusted system paths
        val genericPatterns = listOf("inject", "hook")
        val trustedSystemPaths = listOf(
            "/system/", "/vendor/", "/apex/", "/product/",
            "/system_ext/", "/odm/", "/oem/"
        )

        val found = mutableListOf<String>()
        return try {
            val maps = File("/proc/self/maps").readText()
            maps.lines().forEach { line ->
                if (!line.contains(".so")) return@forEach
                val path = line.trim().split("\\s+".toRegex()).lastOrNull()?.trim() ?: return@forEach
                if (path.isEmpty() || path.startsWith("[") || path.startsWith("anon")) return@forEach

                val filename = path.substringAfterLast("/").lowercase()
                val isSystemPath = trustedSystemPaths.any { path.startsWith(it) }

                val suspicious = suspiciousFilenamePatterns.any { filename.contains(it) } ||
                    (!isSystemPath && genericPatterns.any { filename.contains(it) })

                if (suspicious && !found.contains(path.take(80))) {
                    found.add(path.take(80))
                }
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "injected_libs",
                    name = context.getString(R.string.chk_adv_inj_libs_name),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_adv_inj_libs_desc),
                    detailedReason = context.getString(R.string.chk_adv_inj_libs_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_adv_inj_libs_solution),
                    technicalDetail = "Mapped libs: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "injected_libs",
                    name = "Injected Libraries",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_adv_inj_libs_desc_nd),
                    detailedReason = context.getString(R.string.chk_adv_inj_libs_reason_nd),
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "injected_libs",
                name = "Injected Libraries",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_inj_libs_desc_error),
                detailedReason = "Failed to read /proc/self/maps: ${e.message}",
                solution = context.getString(R.string.chk_adv_inj_libs_solution_error)
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
                    description = context.getString(R.string.chk_adv_zygisk_sock_desc),
                    detailedReason = context.getString(R.string.chk_adv_zygisk_sock_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_adv_zygisk_sock_solution),
                    technicalDetail = "Sockets: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "zygisk_socket",
                    name = "Zygisk Companion Socket",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_adv_zygisk_sock_desc_nd),
                    detailedReason = context.getString(R.string.chk_adv_zygisk_sock_reason_nd),
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "zygisk_socket",
                name = "Zygisk Companion Socket",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_zygisk_sock_desc_error),
                detailedReason = "Failed: ${e.message}",
                solution = context.getString(R.string.chk_adv_zygisk_sock_solution_error)
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
                    name = context.getString(R.string.chk_adv_mgsk_mods_name),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_adv_mgsk_mods_desc, modules.size),
                    detailedReason = context.getString(R.string.chk_adv_mgsk_mods_reason, modules.size, nameList.joinToString(", ") + if (modules.size > 10) "…" else ""),
                    solution = context.getString(R.string.chk_adv_mgsk_mods_solution),
                    technicalDetail = "Modules: ${modules.map { it.name }.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "magisk_module_count",
                    name = "Magisk Modules",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_adv_mgsk_mods_desc_nd),
                    detailedReason = context.getString(R.string.chk_adv_mgsk_mods_reason_nd),
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
                description = context.getString(R.string.chk_adv_mgsk_mods_desc_nodir),
                detailedReason = context.getString(R.string.chk_adv_mgsk_mods_reason_nodir),
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
                    description = context.getString(R.string.chk_adv_debugger_desc),
                    detailedReason = context.getString(R.string.chk_adv_debugger_reason, tracerPid),
                    solution = context.getString(R.string.chk_adv_debugger_solution),
                    technicalDetail = "TracerPid=$tracerPid"
                )
            } else {
                DetectionResult(
                    id = "debugger_attached",
                    name = "Debugger Attached",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_adv_debugger_desc_nd),
                    detailedReason = context.getString(R.string.chk_adv_debugger_reason_nd),
                    solution = "No action required.",
                    technicalDetail = "TracerPid=0"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "debugger_attached",
                name = "Debugger Attached",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_debugger_desc_error),
                detailedReason = "Status read failed: ${e.message}",
                solution = context.getString(R.string.chk_adv_debugger_solution_error)
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
                name = context.getString(R.string.chk_adv_cloaking_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_cloaking_desc),
                detailedReason = context.getString(R.string.chk_adv_cloaking_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_adv_cloaking_solution),
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "root_cloaking",
                name = context.getString(R.string.chk_adv_cloaking_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_adv_cloaking_desc_nd),
                detailedReason = context.getString(R.string.chk_adv_cloaking_reason_nd),
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
                    name = context.getString(R.string.chk_adv_kern_mods_name),
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_adv_kern_mods_desc),
                    detailedReason = context.getString(R.string.chk_adv_kern_mods_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_adv_kern_mods_solution),
                    technicalDetail = "Modules: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "kernel_modules",
                    name = "Root Kernel Modules",
                    category = DetectionCategory.KERNELSU,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_adv_kern_mods_desc_nd),
                    detailedReason = context.getString(R.string.chk_adv_kern_mods_reason_nd),
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "kernel_modules",
                name = "Root Kernel Modules",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_adv_kern_mods_desc_error),
                detailedReason = "Failed: ${e.message}",
                solution = context.getString(R.string.chk_adv_kern_mods_solution_error)
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
