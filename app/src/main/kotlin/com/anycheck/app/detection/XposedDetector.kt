package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import com.anycheck.app.R

/**
 * Detects Xposed Framework, LSPosed, EdXposed, and related hooking / virtual frameworks.
 */
class XposedDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkXposedPackages(),
        checkXposedFiles(),
        checkLSPosedFiles(),
        checkEdXposedFiles(),
        checkXposedBridgeClass(),
        checkXposedInStackTrace(),
        checkXposedProps(),
        checkVirtualFrameworks(),
        checkLSPosedDaemonSocket(),
        checkLSPosedDexInMaps(),
        checkLSPosedConfigFiles(),
        checkHookedMethodDetection(),
        checkLSPosedModuleScope(),
        checkLSPosedSpecificClasses(),
        checkXposedBridgeVersionProp(),
        checkClassLoaderChain(),
        checkInMemoryDexClassLoader(),
        checkLSPosedDataDirs(),
        checkZygiskEnvAndProps(),
        checkLSPosedFullStackTrace(),
        checkSMAPSInlineHooks(),
        checkZygiskModuleInjectionInMaps(),
        checkLspdProcess(),
        checkDataAppScanLSPosed(),
        checkOwnOatLSPosedArtifacts(),
        checkLSPlantNativeLib(),
        checkNativeLSPosedDetection(),
        checkNativeOdexHooks(),
        checkNativeInlineHooks()
    )

    /** Check 1: Xposed / LSPosed / EdXposed manager package names */
    private fun checkXposedPackages(): DetectionResult {
        val xposedPackages = listOf(
            "de.robv.android.xposed.installer",     // Original Xposed Installer
            "org.meowcat.edxposed.manager",          // EdXposed Manager
            "org.meowcat.edxposed.manager.debug",
            "com.solohsu.android.edxp.manager",      // EdXposed (legacy)
            "org.lsposed.manager",                   // LSPosed Manager
            "io.github.lsposed.manager",
            "com.lsposed.manager",
            "io.github.vvb2060.xposeddaemon",
            "io.github.luckyzyx.lsplantmod"          // LSPlant mod
        )
        val found = xposedPackages.filter { packageExists(it) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "xposed_packages",
                name = context.getString(R.string.chk_xposed_packages_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_xposed_packages_desc),
                detailedReason = context.getString(R.string.chk_xposed_packages_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_xposed_packages_solution),
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "xposed_packages",
                name = context.getString(R.string.chk_xposed_packages_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_xposed_packages_desc_nd),
                detailedReason = context.getString(R.string.chk_xposed_packages_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 2: Original Xposed Framework files */
    private fun checkXposedFiles(): DetectionResult {
        val xposedFiles = listOf(
            "/system/framework/XposedBridge.jar",
            "/system/bin/app_process_xposed",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/system/xposed.prop",
            "/system/framework/xposed-framework.jar",
            "/data/data/de.robv.android.xposed.installer"
        )
        val found = xposedFiles.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "xposed_files",
                name = context.getString(R.string.chk_xposed_files_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_xposed_files_desc),
                detailedReason = context.getString(R.string.chk_xposed_files_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_xposed_files_solution),
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "xposed_files",
                name = context.getString(R.string.chk_xposed_files_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_xposed_files_desc_nd),
                detailedReason = context.getString(R.string.chk_xposed_files_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 3: LSPosed module files */
    private fun checkLSPosedFiles(): DetectionResult {
        val lsposedFiles = listOf(
            "/data/adb/modules/lsposed",
            "/data/adb/modules/zygisk_lsposed",
            "/data/adb/modules/riru_lsposed",
            "/data/adb/lspd",
            "/dev/lspd",
            "/data/misc/lspd"
        )
        val found = lsposedFiles.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "lsposed_files",
                name = context.getString(R.string.chk_lsposed_files_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_files_desc),
                detailedReason = context.getString(R.string.chk_lsposed_files_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_lsposed_files_solution),
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "lsposed_files",
                name = context.getString(R.string.chk_lsposed_files_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_files_desc_nd),
                detailedReason = context.getString(R.string.chk_lsposed_files_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 4: EdXposed files */
    private fun checkEdXposedFiles(): DetectionResult {
        val edxposedFiles = listOf(
            "/data/adb/modules/edxposed",
            "/data/adb/edxposed",
            "/data/misc/edxposed_cache",
            "/system/framework/edxp.jar"
        )
        val found = edxposedFiles.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "edxposed_files",
                name = context.getString(R.string.chk_edxposed_files_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_edxposed_files_desc),
                detailedReason = context.getString(R.string.chk_edxposed_files_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_edxposed_files_solution),
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "edxposed_files",
                name = context.getString(R.string.chk_edxposed_files_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_edxposed_files_desc_nd),
                detailedReason = context.getString(R.string.chk_edxposed_files_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 5: Attempt to load the XposedBridge core class */
    private fun checkXposedBridgeClass(): DetectionResult {
        return try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            DetectionResult(
                id = "xposed_bridge_class",
                name = context.getString(R.string.chk_xposed_bridge_class_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_xposed_bridge_class_desc),
                detailedReason = context.getString(R.string.chk_xposed_bridge_class_reason),
                solution = context.getString(R.string.chk_xposed_bridge_class_solution),
                technicalDetail = "Class de.robv.android.xposed.XposedBridge loaded successfully"
            )
        } catch (_: ClassNotFoundException) {
            DetectionResult(
                id = "xposed_bridge_class",
                name = context.getString(R.string.chk_xposed_bridge_class_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_xposed_bridge_class_desc_nd),
                detailedReason = context.getString(R.string.chk_xposed_bridge_class_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        } catch (e: Exception) {
            DetectionResult(
                id = "xposed_bridge_class",
                name = context.getString(R.string.chk_xposed_bridge_class_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_xposed_bridge_class_desc_nd),
                detailedReason = context.getString(R.string.chk_xposed_bridge_class_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 6: Xposed/LSPlant entries in exception stack trace */
    private fun checkXposedInStackTrace(): DetectionResult {
        return try {
            throw Exception("stack_probe")
        } catch (e: Exception) {
            val stackTrace = e.stackTrace.joinToString("\n") { it.toString() }
            val xposedInStack = stackTrace.contains("XposedBridge", ignoreCase = true) ||
                stackTrace.contains("de.robv.android.xposed", ignoreCase = true) ||
                stackTrace.contains("LSPlant", ignoreCase = true) ||
                stackTrace.contains("lsplant", ignoreCase = true)
            if (xposedInStack) {
                DetectionResult(
                    id = "xposed_stack",
                    name = context.getString(R.string.chk_xposed_stack_name),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_xposed_stack_desc),
                    detailedReason = context.getString(R.string.chk_xposed_stack_reason),
                    solution = context.getString(R.string.chk_xposed_stack_solution),
                    technicalDetail = "Stack trace contains XposedBridge or LSPlant entries"
                )
            } else {
                DetectionResult(
                    id = "xposed_stack",
                    name = context.getString(R.string.chk_xposed_stack_name_nd),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_xposed_stack_desc_nd),
                    detailedReason = context.getString(R.string.chk_xposed_stack_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        }
    }

    /** Check 7: Xposed-related system properties */
    private fun checkXposedProps(): DetectionResult {
        val xposedProps = listOf(
            "ro.xposed.installed",
            "ro.xposed.version",
            "persist.sys.xposed.enable"
        )
        val found = mutableListOf<String>()
        xposedProps.forEach { key ->
            val value = getSystemProperty(key)
            if (value.isNotEmpty()) found.add("$key=$value")
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "xposed_props",
                name = context.getString(R.string.chk_xposed_props_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_xposed_props_desc),
                detailedReason = context.getString(R.string.chk_xposed_props_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_xposed_props_solution),
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "xposed_props",
                name = context.getString(R.string.chk_xposed_props_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_xposed_props_desc_nd),
                detailedReason = context.getString(R.string.chk_xposed_props_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 8: Virtual app frameworks (VirtualApp, Parallel Space, etc.) */
    private fun checkVirtualFrameworks(): DetectionResult {
        val virtualFrameworks = listOf(
            "io.va.exposed",                      // VirtualApp exposed
            "com.lody.virtual",                   // VirtualApp
            "com.parallel.space.lite",            // Parallel Space Lite
            "com.lbe.parallel.intl",              // Parallel Space
            "com.excelliance.dualaid",            // Dual Space
            "com.bly.dualspace",                  // Dual Space Pro
            "me.weishu.exp",                      // WeExp
            "com.polestar.nitro",                 // Nitro virtual engine
            "com.doubleagent.android",            // Double Agent
            "com.ludashi.benchmark",
            "com.qihoo360.mobilesafe"             // 360 Safe (may use virtualization)
        )
        val found = virtualFrameworks.filter { packageExists(it) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "virtual_frameworks",
                name = context.getString(R.string.chk_virtual_frameworks_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_virtual_frameworks_desc),
                detailedReason = context.getString(R.string.chk_virtual_frameworks_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_virtual_frameworks_solution),
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "virtual_frameworks",
                name = context.getString(R.string.chk_virtual_frameworks_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_virtual_frameworks_desc_nd),
                detailedReason = context.getString(R.string.chk_virtual_frameworks_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 9: LSPosed daemon Unix socket in /proc/net/unix */
    private fun checkLSPosedDaemonSocket(): DetectionResult {
        val lspdSocketNames = listOf(
            "@lspd",         // LSPosed daemon abstract socket
            "lspd",
            "@lsp",
            "lsposed_daemon",
            "@dev/lspd",
            "/dev/lspd"
        )
        return try {
            val unixContent = File("/proc/net/unix").readText()
            val found = lspdSocketNames.filter { unixContent.contains(it, ignoreCase = true) }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "lsposed_socket",
                    name = context.getString(R.string.chk_lsposed_socket_name),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_lsposed_socket_desc),
                    detailedReason = context.getString(R.string.chk_lsposed_socket_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_lsposed_socket_solution),
                    technicalDetail = "Sockets: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "lsposed_socket",
                    name = context.getString(R.string.chk_lsposed_socket_name_nd),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_lsposed_socket_desc_nd),
                    detailedReason = context.getString(R.string.chk_lsposed_socket_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "lsposed_socket",
                name = context.getString(R.string.chk_lsposed_socket_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_socket_desc_nd),
                detailedReason = context.getString(R.string.chk_lsposed_socket_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 10: LSPosed / LSPlant dex or art files loaded into this process */
    private fun checkLSPosedDexInMaps(): DetectionResult {
        val lsposedFilePatterns = listOf(
            "lsposed",
            "lsplant",
            "lspd",
            "edxp",
            "xposed"
        )
        return try {
            val maps = File("/proc/self/maps").readText()
            val found = mutableListOf<String>()
            maps.lines().forEach { line ->
                val path = line.trim().split("\\s+".toRegex()).lastOrNull()?.trim() ?: return@forEach
                if (path.isEmpty() || path.startsWith("[") || path.startsWith("anon")) return@forEach
                val filename = path.substringAfterLast("/").lowercase()
                // Check for .dex, .art, .jar, .so files with lsposed-related names
                val isRelevantType = filename.endsWith(".dex") || filename.endsWith(".art") ||
                    filename.endsWith(".jar") || filename.endsWith(".so") ||
                    filename.endsWith(".odex") || filename.endsWith(".vdex")
                if (isRelevantType && lsposedFilePatterns.any { filename.contains(it) } &&
                    !found.contains(path.take(80))
                ) {
                    found.add(path.take(80))
                }
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "lsposed_dex_maps",
                    name = context.getString(R.string.chk_lsposed_dex_maps_name),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_lsposed_dex_maps_desc),
                    detailedReason = context.getString(R.string.chk_lsposed_dex_maps_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_lsposed_dex_maps_solution),
                    technicalDetail = "Files: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "lsposed_dex_maps",
                    name = context.getString(R.string.chk_lsposed_dex_maps_name_nd),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_lsposed_dex_maps_desc_nd),
                    detailedReason = context.getString(R.string.chk_lsposed_dex_maps_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "lsposed_dex_maps",
                name = context.getString(R.string.chk_lsposed_dex_maps_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_dex_maps_desc_nd),
                detailedReason = context.getString(R.string.chk_lsposed_dex_maps_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 11: LSPosed configuration / module directories on disk */
    private fun checkLSPosedConfigFiles(): DetectionResult {
        val lsposedConfigPaths = listOf(
            "/data/misc/lspd",
            "/data/misc/lspd/config.json",
            "/data/misc/lspd/modules.json",
            "/data/misc/lspd/enabled_modules.json",
            "/data/adb/lspd",
            "/data/adb/lspd/config",
            "/data/adb/modules/zygisk_lsposed/module.prop",
            "/data/adb/modules/riru_lsposed/module.prop",
            "/data/adb/modules/lsposed/module.prop",
            "/dev/lspd",
            "/data/local/lspd"
        )
        val found = lsposedConfigPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "lsposed_config",
                name = context.getString(R.string.chk_lsposed_config_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_config_desc),
                detailedReason = context.getString(R.string.chk_lsposed_config_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_lsposed_config_solution),
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "lsposed_config",
                name = context.getString(R.string.chk_lsposed_config_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_config_desc_nd),
                detailedReason = context.getString(R.string.chk_lsposed_config_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 12: Hooked method detection via Java reflection.
     *
     * LSPosed (via LSPlant) hooks Java methods by replacing their ArtMethod implementation
     * pointer. When a method is hooked, its declaring class as seen via reflection will be
     * a synthetic proxy class generated by LSPlant, rather than the real declaring class.
     * We probe several well-known methods that Xposed modules commonly target.
     */
    private fun checkHookedMethodDetection(): DetectionResult {
        val hookedMethods = mutableListOf<String>()
        val methodsToCheck = listOf(
            Triple("java.lang.Object", "hashCode", emptyArray<Class<*>>()),
            Triple("java.lang.Object", "equals", arrayOf<Class<*>>(Object::class.java)),
            Triple("android.app.Application", "onCreate", emptyArray<Class<*>>()),
            Triple("android.content.pm.PackageManager", "getPackageInfo",
                arrayOf<Class<*>>(String::class.java, Int::class.javaPrimitiveType!!))
        )
        methodsToCheck.forEach { (className, methodName, params) ->
            try {
                val clazz = Class.forName(className)
                val method = clazz.getDeclaredMethod(methodName, *params)
                val declaringClass = method.declaringClass.name
                // If the declaring class name contains synthetic hook indicators, it's hooked.
                // LSPlant proxy classes typically have "$Xposed" or "XC_Method" or unusual names.
                val hookIndicators = listOf(
                    "xposed", "lsplant", "\$xc_", "hooker", "hook_",
                    "methodhook", "xc_method", "xposedbridge"
                )
                if (hookIndicators.any { declaringClass.contains(it, ignoreCase = true) }) {
                    hookedMethods.add("$className.$methodName (declared by: $declaringClass)")
                }
                // Also check via toString — hooked methods sometimes show abnormal toString
                val methodStr = method.toString().lowercase()
                if (hookIndicators.any { methodStr.contains(it) }) {
                    val entry = "$className.$methodName"
                    if (!hookedMethods.contains(entry)) hookedMethods.add(entry)
                }
            } catch (_: Exception) {}
        }

        // Additional: probe exception stack for LSPlant hook frames
        try {
            throw RuntimeException("hook_probe")
        } catch (e: RuntimeException) {
            e.stackTrace.forEach { frame ->
                val cls = frame.className.lowercase()
                val mth = frame.methodName.lowercase()
                if (cls.contains("lsplant") || cls.contains("xposedbridge") ||
                    mth.contains("invokeoriginalmethod") || cls.contains("methodhook")
                ) {
                    hookedMethods.add("StackFrame: ${frame.className}.${frame.methodName}")
                }
            }
        }

        return if (hookedMethods.isNotEmpty()) {
            DetectionResult(
                id = "hooked_methods",
                name = context.getString(R.string.chk_hooked_methods_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_hooked_methods_desc),
                detailedReason = context.getString(R.string.chk_hooked_methods_reason, hookedMethods.take(5).joinToString(", ")),
                solution = context.getString(R.string.chk_hooked_methods_solution),
                technicalDetail = hookedMethods.take(10).joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "hooked_methods",
                name = context.getString(R.string.chk_hooked_methods_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_hooked_methods_desc_nd),
                detailedReason = context.getString(R.string.chk_hooked_methods_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 13: LSPosed module scope — detect if any LSPosed module is scoped to this app.
     * LSPosed records module scopes in /data/misc/lspd/. If we can read a JSON config file
     * that lists our package, it confirms a module is targeting us.
     */
    private fun checkLSPosedModuleScope(): DetectionResult {
        val ourPackage = context.packageName
        val configFiles = listOf(
            "/data/misc/lspd/config.json",
            "/data/misc/lspd/modules.json",
            "/data/misc/lspd/enabled_modules.json",
            "/data/adb/lspd/config"
        )
        val matchingFiles = mutableListOf<String>()
        configFiles.forEach { path ->
            try {
                val content = File(path).readText()
                if (content.contains(ourPackage, ignoreCase = true)) {
                    matchingFiles.add(path)
                }
            } catch (_: Exception) {}
        }

        // Also try /data/misc/lspd/modules/ directory — each module may have a scope file
        try {
            val modulesDir = File("/data/misc/lspd")
            if (modulesDir.exists()) {
                modulesDir.walk().maxDepth(3).forEach { file ->
                    if (file.isFile && (file.name.endsWith(".json") || file.name.endsWith(".list"))) {
                        try {
                            if (file.readText().contains(ourPackage, ignoreCase = true)) {
                                matchingFiles.add(file.path)
                            }
                        } catch (_: Exception) {}
                    }
                }
            }
        } catch (_: Exception) {}

        return if (matchingFiles.isNotEmpty()) {
            DetectionResult(
                id = "lsposed_module_scope",
                name = context.getString(R.string.chk_lsposed_scope_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_scope_desc),
                detailedReason = context.getString(R.string.chk_lsposed_scope_reason, ourPackage, matchingFiles.joinToString(", ")),
                solution = context.getString(R.string.chk_lsposed_scope_solution),
                technicalDetail = "Scope files: ${matchingFiles.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "lsposed_module_scope",
                name = context.getString(R.string.chk_lsposed_scope_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_scope_desc_nd),
                detailedReason = context.getString(R.string.chk_lsposed_scope_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 14: Load LSPosed-specific internal classes.
     * LSPosed injects its startup classes into every hooked process.
     * If these classes are loadable, LSPosed is definitively active in this process.
     */
    private fun checkLSPosedSpecificClasses(): DetectionResult {
        val lsposedClasses = listOf(
            "org.lsposed.lspd.core.Startup",
            "org.lsposed.lspd.nativebridge.NativeAPI",
            "org.lsposed.lspd.nativebridge.ModuleLogger",
            "io.github.lsposed.lspd.core.Startup",
            "io.github.lsposed.lspd.service.ILSPosedService",
            "org.lsposed.lspd.service.ILSPosedService",
            "com.solohsu.android.edxp.manager.service.IEdXpService"
        )
        val found = mutableListOf<String>()
        lsposedClasses.forEach { className ->
            try {
                Class.forName(className)
                found.add(className)
            } catch (_: ClassNotFoundException) {}
            catch (_: Exception) {}
        }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "lsposed_classes",
                name = context.getString(R.string.chk_lsposed_classes_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_classes_desc),
                detailedReason = context.getString(R.string.chk_lsposed_classes_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_lsposed_classes_solution),
                technicalDetail = "Classes: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "lsposed_classes",
                name = context.getString(R.string.chk_lsposed_classes_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_classes_desc_nd),
                detailedReason = context.getString(R.string.chk_lsposed_classes_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 15: XposedBridge version system property and related Xposed bridge fields.
     * When the Xposed/LSPosed framework is active, it sets several system properties and
     * also exposes specific fields on the XposedBridge class (disableHooks, hookCount).
     */
    private fun checkXposedBridgeVersionProp(): DetectionResult {
        val xposedSystemProps = listOf(
            "xposed.bridge.version",
            "de.robv.android.xposed.version",
            "org.lsposed.version"
        )
        val found = mutableListOf<String>()

        // Check via System.getProperty
        xposedSystemProps.forEach { key ->
            try {
                val v = System.getProperty(key)
                if (!v.isNullOrEmpty()) found.add("$key=$v")
            } catch (_: Exception) {}
        }

        // Check via SystemProperties reflection (reads build.prop-layer props)
        xposedSystemProps.forEach { key ->
            try {
                val sp = Class.forName("android.os.SystemProperties")
                val v = sp.getMethod("get", String::class.java, String::class.java)
                    .invoke(null, key, "") as String
                if (v.isNotEmpty() && !found.any { it.startsWith(key) }) {
                    found.add("$key=$v (sp)")
                }
            } catch (_: Exception) {}
        }

        // Check XposedBridge.disableHooks and getXposedVersion() if class is accessible
        try {
            val bridgeClass = Class.forName("de.robv.android.xposed.XposedBridge")
            try {
                bridgeClass.getField("disableHooks")
                found.add("XposedBridge.disableHooks field accessible")
            } catch (_: NoSuchFieldException) {}
            try {
                val versionMethod = bridgeClass.getMethod("getXposedVersion")
                val version = versionMethod.invoke(null)
                found.add("XposedBridge.getXposedVersion()=$version")
            } catch (_: Exception) {}
        } catch (_: ClassNotFoundException) {}
        catch (_: Exception) {}

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "xposed_bridge_version",
                name = context.getString(R.string.chk_xposed_bridge_version_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_xposed_bridge_version_desc),
                detailedReason = context.getString(R.string.chk_xposed_bridge_version_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_xposed_bridge_version_solution),
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "xposed_bridge_version",
                name = context.getString(R.string.chk_xposed_bridge_version_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_xposed_bridge_version_desc_nd),
                detailedReason = context.getString(R.string.chk_xposed_bridge_version_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 16: ClassLoader chain analysis.
     * LSPosed injects additional ClassLoaders into the app's ClassLoader hierarchy.
     * Walking the parent chain and inspecting class names can reveal lsposed/lspd loaders.
     */
    private fun checkClassLoaderChain(): DetectionResult {
        val suspiciousLoaders = mutableListOf<String>()
        val hookKeywords = listOf("lsposed", "lspd", "edxposed", "edxp", "xposed", "riru", "zygisk")

        try {
            var loader: ClassLoader? = context.classLoader
            var depth = 0
            while (loader != null && depth < 20) {
                val loaderName = loader.javaClass.name.lowercase()
                val loaderStr = loader.toString().lowercase()
                hookKeywords.forEach { kw ->
                    if ((loaderName.contains(kw) || loaderStr.contains(kw)) &&
                        !suspiciousLoaders.any { it.contains(kw) }
                    ) {
                        suspiciousLoaders.add("${loader.javaClass.name}[d=$depth]")
                    }
                }
                // Also check parent class name via reflection
                try {
                    val parentField = loader.javaClass.getDeclaredField("parent")
                    parentField.isAccessible = true
                    loader = parentField.get(loader) as? ClassLoader
                } catch (_: Exception) {
                    loader = loader?.parent
                }
                depth++
            }
        } catch (_: Exception) {}

        // Also inspect Thread's contextClassLoader
        try {
            val ctxLoader = Thread.currentThread().contextClassLoader
            val name = ctxLoader?.javaClass?.name?.lowercase() ?: ""
            if (hookKeywords.any { name.contains(it) } && !suspiciousLoaders.any { it.contains(name) }) {
                suspiciousLoaders.add("contextClassLoader=${ctxLoader?.javaClass?.name}")
            }
        } catch (_: Exception) {}

        return if (suspiciousLoaders.isNotEmpty()) {
            DetectionResult(
                id = "classloader_chain",
                name = context.getString(R.string.chk_classloader_chain_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_classloader_chain_desc),
                detailedReason = context.getString(R.string.chk_classloader_chain_reason, suspiciousLoaders.joinToString(", ")),
                solution = context.getString(R.string.chk_classloader_chain_solution),
                technicalDetail = suspiciousLoaders.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "classloader_chain",
                name = context.getString(R.string.chk_classloader_chain_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_classloader_chain_desc_nd),
                detailedReason = context.getString(R.string.chk_classloader_chain_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 17: In-memory DEX ClassLoader detection.
     * LSPosed loads Xposed module DEX files directly into memory using InMemoryDexClassLoader.
     * By inspecting the app's ClassLoader dexElements via reflection, we can detect
     * anonymous/in-memory DEX entries that have no file path — a strong LSPosed signature.
     */
    private fun checkInMemoryDexClassLoader(): DetectionResult {
        val suspiciousEntries = mutableListOf<String>()

        try {
            var loader: ClassLoader? = context.classLoader
            var depth = 0
            while (loader != null && depth < 15) {
                val loaderClass = loader.javaClass
                val loaderSuperClass = loaderClass.superclass

                // Check if this is an InMemoryDexClassLoader by class name
                val loaderName = loaderClass.name
                if (loaderName.contains("InMemoryDexClassLoader")) {
                    suspiciousEntries.add("InMemoryDexClassLoader at depth $depth")
                }

                // Deep reflection into BaseDexClassLoader.pathList.dexElements
                val isBaseDex = loaderName.contains("BaseDexClassLoader") ||
                    (loaderSuperClass?.name?.contains("BaseDexClassLoader") == true)
                if (isBaseDex || loaderName.contains("DexClassLoader") ||
                    loaderName.contains("PathClassLoader")
                ) {
                    try {
                        // Walk up class hierarchy to find pathList field
                        var searchClass: Class<*>? = loaderClass
                        var pathListField: java.lang.reflect.Field? = null
                        while (searchClass != null && pathListField == null) {
                            try {
                                pathListField = searchClass.getDeclaredField("pathList")
                            } catch (_: NoSuchFieldException) {}
                            searchClass = searchClass.superclass
                        }
                        pathListField?.let { plf ->
                            plf.isAccessible = true
                            val pathList = plf.get(loader) ?: return@let
                            val dexElementsField = pathList.javaClass.getDeclaredField("dexElements")
                            dexElementsField.isAccessible = true
                            val dexElements = dexElementsField.get(pathList) as? Array<*>
                            dexElements?.forEachIndexed { idx, element ->
                                try {
                                    val dexFileField = element!!.javaClass.getDeclaredField("dexFile")
                                    dexFileField.isAccessible = true
                                    val dexFile = dexFileField.get(element) ?: return@forEachIndexed
                                    val dexStr = dexFile.toString()
                                    // In-memory DEX has "InMemoryDexFile" or empty/null path
                                    if (dexStr.contains("InMemoryDexFile") ||
                                        dexStr.contains("cookie=")
                                    ) {
                                        // Try to get actual file name
                                        val fileName = runCatching {
                                            dexFile.javaClass.getDeclaredMethod("getName")
                                                .also { it.isAccessible = true }
                                                .invoke(dexFile) as? String
                                        }.getOrNull()
                                        if (fileName == null || !fileName.startsWith("/")) {
                                            suspiciousEntries.add(
                                                "InMemoryDex[d=$depth,e=$idx]=${dexStr.take(60)}"
                                            )
                                        }
                                    }
                                } catch (_: Exception) {}
                            }
                        }
                    } catch (_: Exception) {}
                }

                loader = try { loader.parent } catch (_: Exception) { null }
                depth++
            }
        } catch (_: Exception) {}

        return if (suspiciousEntries.isNotEmpty()) {
            DetectionResult(
                id = "in_memory_dex",
                name = context.getString(R.string.chk_in_memory_dex_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_in_memory_dex_desc),
                detailedReason = context.getString(R.string.chk_in_memory_dex_reason, suspiciousEntries.take(5).joinToString(", ")),
                solution = context.getString(R.string.chk_in_memory_dex_solution),
                technicalDetail = suspiciousEntries.take(8).joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "in_memory_dex",
                name = context.getString(R.string.chk_in_memory_dex_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_in_memory_dex_desc_nd),
                detailedReason = context.getString(R.string.chk_in_memory_dex_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 18: LSPosed application data directories.
     * Even if LSPosed Manager is hidden from PackageManager via Magisk DenyList,
     * its data directory under /data/user/0/ or /data/data/ may still exist.
     */
    private fun checkLSPosedDataDirs(): DetectionResult {
        val dataDirPatterns = listOf(
            "/data/user/0/org.lsposed.manager",
            "/data/user/0/io.github.lsposed.manager",
            "/data/user/0/com.lsposed.manager",
            "/data/data/org.lsposed.manager",
            "/data/data/io.github.lsposed.manager",
            "/data/data/com.lsposed.manager",
            "/data/user/0/org.meowcat.edxposed.manager",
            "/data/data/org.meowcat.edxposed.manager",
            "/data/user/0/com.solohsu.android.edxp.manager",
            "/data/data/de.robv.android.xposed.installer"
        )
        val found = dataDirPatterns.filter { File(it).exists() }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "lsposed_data_dirs",
                name = context.getString(R.string.chk_lsposed_data_dirs_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_lsposed_data_dirs_desc),
                detailedReason = context.getString(R.string.chk_lsposed_data_dirs_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_lsposed_data_dirs_solution),
                technicalDetail = "Dirs: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "lsposed_data_dirs",
                name = context.getString(R.string.chk_lsposed_data_dirs_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_lsposed_data_dirs_desc_nd),
                detailedReason = context.getString(R.string.chk_lsposed_data_dirs_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 19: Zygisk environment variable and system properties.
     * Zygisk (built into Magisk) and Zygisk Next set specific environment variables and
     * system properties that can be read from within an app process.
     * - ZYGISK_ENABLED env var (set by older Magisk/Zygisk)
     * - ro.zygisk.denylists (Zygisk Next / ZygiskSU feature)
     * - persist.sys.zygisk.enable
     */
    private fun checkZygiskEnvAndProps(): DetectionResult {
        val found = mutableListOf<String>()

        // Environment variables
        try {
            val zygiskEnabled = System.getenv("ZYGISK_ENABLED")
            if (!zygiskEnabled.isNullOrEmpty() && zygiskEnabled != "0") {
                found.add("ZYGISK_ENABLED=$zygiskEnabled")
            }
        } catch (_: Exception) {}

        // System properties via reflection (more reliable than getprop)
        val zygiskProps = listOf(
            "ro.zygisk.denylists",
            "persist.sys.zygisk.enable",
            "persist.zygisk.enabled",
            "ro.zygisk.enable",
            "magisk.process",
            "ro.boot.vbmeta.device_state"  // Often set to "unlocked" on Magisk devices
        )
        zygiskProps.forEach { key ->
            try {
                val sp = Class.forName("android.os.SystemProperties")
                val v = sp.getMethod("get", String::class.java, String::class.java)
                    .invoke(null, key, "") as String
                if (v.isNotEmpty() && !listOf("0", "false", "locked").contains(v)) {
                    found.add("$key=$v")
                }
            } catch (_: Exception) {}
        }

        // Also check via getprop for zygisk props
        listOf("ro.zygisk.denylists", "persist.sys.zygisk.enable").forEach { key ->
            try {
                val v = getSystemProperty(key)
                if (v.isNotEmpty() && !found.any { it.startsWith(key) }) {
                    found.add("$key=$v (getprop)")
                }
            } catch (_: Exception) {}
        }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "zygisk_env",
                name = context.getString(R.string.chk_zygisk_env_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_zygisk_env_desc),
                detailedReason = context.getString(R.string.chk_zygisk_env_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_zygisk_env_solution),
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "zygisk_env",
                name = context.getString(R.string.chk_zygisk_env_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_zygisk_env_desc_nd),
                detailedReason = context.getString(R.string.chk_zygisk_env_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 20: Extended LSPosed/lspd stack trace scan.
     * Complements check 6 by specifically looking for lsposed, lspd, and edxposed
     * class names in the exception stack trace — patterns that check 6 does not cover.
     */
    private fun checkLSPosedFullStackTrace(): DetectionResult {
        val found = mutableListOf<String>()
        val lsposedPatterns = listOf(
            "lsposed", "lspd", "edxposed", "edxp", "handleloadpackage",
            "xc_methodhook", "xposedbridge"
        )
        try {
            throw Exception("lspd_stack_probe")
        } catch (e: Exception) {
            e.stackTrace.forEach { frame ->
                val cls = frame.className.lowercase()
                val match = lsposedPatterns.firstOrNull { cls.contains(it) }
                if (match != null) {
                    val entry = "${frame.className}.${frame.methodName}"
                    if (!found.contains(entry)) found.add(entry)
                }
            }
        }
        // Also enumerate all threads and probe their stack traces
        try {
            Thread.getAllStackTraces().forEach { (_, frames) ->
                frames.forEach { frame ->
                    val cls = frame.className.lowercase()
                    val match = lsposedPatterns.firstOrNull { cls.contains(it) }
                    if (match != null) {
                        val entry = "${frame.className}.${frame.methodName}"
                        if (!found.contains(entry)) found.add(entry)
                    }
                }
            }
        } catch (_: Exception) {}
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "lsposed_stack_full",
                name = context.getString(R.string.chk_lsposed_stack_full_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_stack_full_desc),
                detailedReason = context.getString(R.string.chk_lsposed_stack_full_reason, found.take(5).joinToString(", ")),
                solution = context.getString(R.string.chk_lsposed_stack_full_solution),
                technicalDetail = found.take(10).joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "lsposed_stack_full",
                name = context.getString(R.string.chk_lsposed_stack_full_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsposed_stack_full_desc_nd),
                detailedReason = context.getString(R.string.chk_lsposed_stack_full_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 21: SMAPS Private_Dirty inline-hook detection.
     * When a hook framework (LSPosed/Frida/Zygisk module) patches code in a read-only (.text)
     * segment of a shared library, the kernel Copy-on-Write mechanism marks those pages as
     * Private_Dirty. On a clean device every r-xp code segment of libc/libart has
     * Private_Dirty == 0. A non-zero value is a reliable indicator of an inline hook.
     */
    private fun checkSMAPSInlineHooks(): DetectionResult {
        val suspiciousLibs = mutableListOf<String>()
        val criticalLibs = setOf("libart.so", "libc.so", "libandroid_runtime.so", "libbinder.so")
        try {
            var currentLib: String? = null
            var inCodeSegment = false
            File("/proc/self/smaps").forEachLine { line ->
                val trimmed = line.trim()
                // New mapping header: starts with hex address range
                if (trimmed.matches(Regex("^[0-9a-f]+-[0-9a-f]+.*"))) {
                    val parts = trimmed.split("\\s+".toRegex())
                    val perms = parts.getOrNull(1) ?: ""
                    val path = parts.lastOrNull()?.takeIf { it.startsWith("/") } ?: ""
                    val filename = path.substringAfterLast("/")
                    inCodeSegment = perms == "r-xp" && criticalLibs.contains(filename)
                    currentLib = if (inCodeSegment) filename else null
                } else if (inCodeSegment && trimmed.startsWith("Private_Dirty:")) {
                    val kb = trimmed.substringAfter("Private_Dirty:").trim()
                        .substringBefore(" ").trim().toLongOrNull() ?: 0L
                    if (kb > 0L) {
                        val entry = "$currentLib (Private_Dirty=${kb}kB)"
                        if (!suspiciousLibs.contains(entry)) suspiciousLibs.add(entry)
                    }
                }
            }
        } catch (_: Exception) {}
        return if (suspiciousLibs.isNotEmpty()) {
            DetectionResult(
                id = "smaps_inline_hooks",
                name = context.getString(R.string.chk_smaps_hooks_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_smaps_hooks_desc),
                detailedReason = context.getString(R.string.chk_smaps_hooks_reason, suspiciousLibs.joinToString(", ")),
                solution = context.getString(R.string.chk_smaps_hooks_solution),
                technicalDetail = "Dirty code segments: ${suspiciousLibs.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "smaps_inline_hooks",
                name = context.getString(R.string.chk_smaps_hooks_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_smaps_hooks_desc_nd),
                detailedReason = context.getString(R.string.chk_smaps_hooks_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 22: Generic Zygisk module injection in /proc/self/maps.
     * When a Zygisk module (any module, not just LSPosed) is loaded into this process,
     * its native library appears in the process memory map under a path matching
     * /data/adb/modules/<name>/zygisk/. Detecting this path confirms Zygisk injection
     * is active for this app regardless of which module is responsible.
     */
    private fun checkZygiskModuleInjectionInMaps(): DetectionResult {
        val injectedModules = mutableListOf<String>()
        try {
            File("/proc/self/maps").forEachLine { line ->
                val path = line.trim().split("\\s+".toRegex()).lastOrNull() ?: return@forEachLine
                // Match /data/adb/modules/<module_name>/zygisk/
                if (path.contains("/data/adb/modules/") && path.contains("/zygisk/")) {
                    val entry = path.take(120)
                    if (!injectedModules.contains(entry)) injectedModules.add(entry)
                }
            }
        } catch (_: Exception) {}
        return if (injectedModules.isNotEmpty()) {
            DetectionResult(
                id = "zygisk_module_injection",
                name = context.getString(R.string.chk_zygisk_module_inject_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_zygisk_module_inject_desc),
                detailedReason = context.getString(R.string.chk_zygisk_module_inject_reason, injectedModules.take(5).joinToString(", ")),
                solution = context.getString(R.string.chk_zygisk_module_inject_solution),
                technicalDetail = "Mapped paths: ${injectedModules.take(10).joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "zygisk_module_injection",
                name = context.getString(R.string.chk_zygisk_module_inject_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_zygisk_module_inject_desc_nd),
                detailedReason = context.getString(R.string.chk_zygisk_module_inject_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 23: LSPosed daemon (lspd) process detection.
     * Scans /proc for a running process whose command line matches "lspd".
     * The lspd daemon is the background service that manages the LSPosed
     * framework; its presence in the process list confirms LSPosed is active
     * even when other indicators have been hidden.
     */
    private fun checkLspdProcess(): DetectionResult {
        val foundPids = mutableListOf<String>()
        try {
            val procDir = File("/proc")
            procDir.listFiles { _, name -> name.all { it.isDigit() } }?.forEach { pidDir ->
                val name = pidDir.name
                try {
                    val cmdline = File(pidDir, "cmdline").readText()
                        .replace('\u0000', ' ').trim()
                    // Match the process name "lspd" exactly (as the first token)
                    // to avoid false-matching processes like "lspdump" etc.
                    val procName = cmdline.split(" ").firstOrNull()
                        ?.substringAfterLast("/") ?: return@forEach
                    if (procName == "lspd") {
                        foundPids.add("pid=$name cmdline=${cmdline.take(80)}")
                    }
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}

        return if (foundPids.isNotEmpty()) {
            DetectionResult(
                id = "lspd_process",
                name = context.getString(R.string.chk_lspd_process_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lspd_process_desc),
                detailedReason = context.getString(R.string.chk_lspd_process_reason, foundPids.joinToString("; ")),
                solution = context.getString(R.string.chk_lspd_process_solution),
                technicalDetail = foundPids.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "lspd_process",
                name = context.getString(R.string.chk_lspd_process_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lspd_process_desc_nd),
                detailedReason = context.getString(R.string.chk_lspd_process_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 24: /data/app directory scan for LSPosed / EdXposed / HMA.
     *
     * DenyList / Shamiko / HMA can all hide packages from PackageManager
     * queries, but none of them can remove the APK installation directories
     * created by the Android installer in /data/app.  Scanning those
     * directories gives us ground-truth evidence of package installation that
     * bypasses all PM-level hooks.
     *
     * Android 9+ layout:  /data/app/~~RANDOM==/PACKAGE-RANDOM==/base.apk
     * Android 7–8 layout: /data/app/PACKAGE-N/base.apk
     */
    private fun checkDataAppScanLSPosed(): DetectionResult {
        val targets = arrayOf(
            "org.lsposed.manager",
            "io.github.lsposed.manager",
            "com.lsposed.manager",
            "org.meowcat.edxposed.manager",
            "com.solohsu.android.edxp.manager",
            "de.robv.android.xposed.installer",
            // HMA is also included here so a single /data/app pass covers both
            "com.tsng.hidemyapplist",
            "com.tsng.hidemyapplist.debug",
            "cn.hidemyapplist"
        )
        val found = scanDataAppForPackages(*targets)
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "data_app_scan_lsposed",
                name = context.getString(R.string.chk_data_app_scan_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_data_app_scan_desc),
                detailedReason = context.getString(
                    R.string.chk_data_app_scan_reason,
                    found.joinToString("; ")
                ),
                solution = context.getString(R.string.chk_data_app_scan_solution),
                technicalDetail = found.joinToString("\n")
            )
        } else {
            DetectionResult(
                id = "data_app_scan_lsposed",
                name = context.getString(R.string.chk_data_app_scan_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_data_app_scan_desc_nd),
                detailedReason = context.getString(R.string.chk_data_app_scan_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /**
     * Check 25: OAT self-state — detect LSPosed artefacts in AnyCheck's own
     * install directory.
     *
     * When LSPosed hooks methods in a target app it needs to deoptimise them
     * (remove their compiled machine code so the DEX interpreter runs instead,
     * allowing hook trampolines to fire).  To do this it writes an in-process
     * profile hint and may drop extra DEX / ODEX / VDEX files into the target
     * app's OAT directory.  On a clean device only `base.odex` + `base.vdex`
     * (and optionally `base.art`) exist there.  Any unexpected extra file is a
     * strong indicator of hook-framework interference.
     *
     * We also check whether our own OAT file starts with the standard ART
     * magic bytes ("oat\n").  A modified header (e.g. zeroed or patched magic)
     * is another indicator.
     *
     * The derivation path is:
     *   applicationInfo.sourceDir
     *     → e.g. /data/app/~~ABC==/com.anycheck.app-XYZ==/base.apk
     *   oatDir = installDir/oat/<abi>/
     */
    private fun checkOwnOatLSPosedArtifacts(): DetectionResult {
        val indicators = mutableListOf<String>()
        try {
            val sourceDir = context.applicationInfo.sourceDir
            val installDir = File(sourceDir).parentFile
                ?: return notDetectedOat()

            // Try each ABI subdirectory that might exist
            val abis = listOf("arm64", "arm", "x86_64", "x86")
            for (abi in abis) {
                val oatDir = File(installDir, "oat/$abi")
                if (!oatDir.isDirectory) continue

                val files = oatDir.listFiles() ?: continue
                val fileNames = files.map { it.name }.toSet()

                // Known-good artefacts produced by dex2oat
                val expected = setOf("base.odex", "base.vdex", "base.art")
                val unexpected = files.filter { it.name !in expected }
                if (unexpected.isNotEmpty()) {
                    indicators.add(
                        "Unexpected files in oat/$abi: ${unexpected.joinToString { it.name }}"
                    )
                }

                val odexFile = File(oatDir, "base.odex")
                if (odexFile.exists() && odexFile.length() >= 4) {
                    try {
                        odexFile.inputStream().use { stream ->
                            val header = ByteArray(4)
                            stream.read(header)
                            // Standard ART OAT magic: 'o' 'a' 't' '\n' (0x6f 0x61 0x74 0x0a)
                            val valid = header[0] == 0x6f.toByte() &&
                                header[1] == 0x61.toByte() &&
                                header[2] == 0x74.toByte() &&
                                header[3] == 0x0a.toByte()
                            if (!valid) {
                                indicators.add(
                                    "Unexpected OAT magic in oat/$abi/base.odex: " +
                                        header.joinToString("") { "%02x".format(it) }
                                )
                            }
                        }
                    } catch (_: Exception) {}

                    // Scan ODEX binary for LSPosed/LSPlant string markers.
                    // When LSPosed is active its framework strings may be baked
                    // into the compiled OAT code or embedded in the DEX string pool
                    // that is embedded in the ODEX.  This mirrors the technique
                    // used by reveny/Android-Native-Root-Detector to detect LSPosed
                    // by inspecting its own compiled artefact.
                    try {
                        val lsposedMarkers = listOf(
                            "lsposed", "lsplant", "liblsplant", "lspd",
                            "edxposed", "xposedbridge", "XposedBridge",
                            "de.robv.android.xposed"
                        )
                        val odexBytes = odexFile.readBytes()
                        val odexText = String(odexBytes, Charsets.ISO_8859_1)
                        for (marker in lsposedMarkers) {
                            if (odexText.contains(marker, ignoreCase = true)) {
                                indicators.add(
                                    "LSPosed marker \"$marker\" found in oat/$abi/base.odex"
                                )
                                break // one marker is sufficient evidence
                            }
                        }
                    } catch (_: Exception) {}
                }

                // A missing odex but present vdex alone can indicate forced
                // interpreter mode (which LSPosed uses on some Android versions)
                if ("base.vdex" in fileNames && "base.odex" !in fileNames) {
                    indicators.add(
                        "oat/$abi has base.vdex but no base.odex — " +
                            "possible forced-interpreter deoptimisation"
                    )
                }
            }
        } catch (_: Exception) {}

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "own_oat_artifacts",
                name = context.getString(R.string.chk_own_oat_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_own_oat_desc),
                detailedReason = context.getString(
                    R.string.chk_own_oat_reason,
                    indicators.joinToString("; ")
                ),
                solution = context.getString(R.string.chk_own_oat_solution),
                technicalDetail = indicators.joinToString("\n")
            )
        } else {
            notDetectedOat()
        }
    }

    private fun notDetectedOat() = DetectionResult(
        id = "own_oat_artifacts",
        name = context.getString(R.string.chk_own_oat_name_nd),
        category = DetectionCategory.XPOSED,
        status = DetectionStatus.NOT_DETECTED,
        riskLevel = RiskLevel.HIGH,
        description = context.getString(R.string.chk_own_oat_desc_nd),
        detailedReason = context.getString(R.string.chk_own_oat_reason_nd),
        solution = context.getString(R.string.chk_no_action_needed)
    )

    /**
     * Check 26: LSPlant native library in process memory map.
     *
     * LSPlant is the ART hooking engine that powers LSPosed.  When LSPosed is
     * active and has hooked at least one method in this app, it loads its
     * native library (liblsplant.so) and potentially other support libs
     * (liblsposed.so, libxposed-native.so, liblspd.so) into the process.
     * These appear as named mappings in /proc/self/maps even when the DEX-level
     * checks are bypassed.
     *
     * Note: if no module targets this app, LSPlant may not be mapped here —
     * this check is complementary to the other LSPosed checks.
     */
    private fun checkLSPlantNativeLib(): DetectionResult {
        val lsplantLibs = listOf(
            "liblsplant.so",
            "liblsposed.so",
            "libxposed-native.so",
            "liblspd.so",
            "liblspatch.so",
            "libfake-linker.so"   // used by LSPosed's zygisk variant
        )
        val found = mutableListOf<String>()
        try {
            File("/proc/self/maps").forEachLine { line ->
                val path = line.trim().split("\\s+".toRegex()).lastOrNull()
                    ?.takeIf { it.startsWith("/") } ?: return@forEachLine
                val filename = path.substringAfterLast("/")
                val match = lsplantLibs.firstOrNull { filename.equals(it, ignoreCase = true) }
                if (match != null) {
                    val entry = path.take(120)
                    if (!found.contains(entry)) found.add(entry)
                }
            }
        } catch (_: Exception) {}

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "lsplant_native_lib",
                name = context.getString(R.string.chk_lsplant_native_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsplant_native_desc),
                detailedReason = context.getString(
                    R.string.chk_lsplant_native_reason,
                    found.joinToString("; ")
                ),
                solution = context.getString(R.string.chk_lsplant_native_solution),
                technicalDetail = "Mapped libs: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "lsplant_native_lib",
                name = context.getString(R.string.chk_lsplant_native_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_lsplant_native_desc_nd),
                detailedReason = context.getString(R.string.chk_lsplant_native_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 27: Native C++ LSPosed detection (bypasses LSPlant Java hooks) */
    private fun checkNativeLSPosedDetection(): DetectionResult {
        val findings = NativeDetector.detectLSPosed()
        return if (findings.isNotEmpty()) {
            DetectionResult(
                id = "native_lsposed_detect",
                name = context.getString(R.string.chk_native_lsposed_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_native_lsposed_desc),
                detailedReason = context.getString(R.string.chk_native_lsposed_reason, findings),
                solution = context.getString(R.string.chk_native_lsposed_solution),
                technicalDetail = findings
            )
        } else {
            DetectionResult(
                id = "native_lsposed_detect",
                name = context.getString(R.string.chk_native_lsposed_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_native_lsposed_desc_nd),
                detailedReason = context.getString(R.string.chk_native_lsposed_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 28: Native ODEX self-scan (bypasses Java-layer file I/O hooks) */
    private fun checkNativeOdexHooks(): DetectionResult {
        val findings = NativeDetector.detectOdexHooks()
        return if (findings.isNotEmpty()) {
            DetectionResult(
                id = "native_odex_hooks",
                name = context.getString(R.string.chk_native_odex_hooks_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_native_odex_hooks_desc),
                detailedReason = context.getString(R.string.chk_native_odex_hooks_reason, findings),
                solution = context.getString(R.string.chk_native_odex_hooks_solution),
                technicalDetail = findings
            )
        } else {
            DetectionResult(
                id = "native_odex_hooks",
                name = context.getString(R.string.chk_native_odex_hooks_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_native_odex_hooks_desc_nd),
                detailedReason = context.getString(R.string.chk_native_odex_hooks_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    /** Check 29: Native inline-hook trampoline detection */
    private fun checkNativeInlineHooks(): DetectionResult {
        val findings = NativeDetector.detectInlineHooks()
        return if (findings.isNotEmpty()) {
            DetectionResult(
                id = "native_inline_hooks",
                name = context.getString(R.string.chk_native_inline_hooks_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_native_inline_hooks_desc),
                detailedReason = context.getString(R.string.chk_native_inline_hooks_reason, findings),
                solution = context.getString(R.string.chk_native_inline_hooks_solution),
                technicalDetail = findings
            )
        } else {
            DetectionResult(
                id = "native_inline_hooks",
                name = context.getString(R.string.chk_native_inline_hooks_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_native_inline_hooks_desc_nd),
                detailedReason = context.getString(R.string.chk_native_inline_hooks_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ---- Utilities ----

    /**
     * Scans /data/app for installed package directories whose names match any
     * of the supplied package name prefixes.  This reads the filesystem
     * directly, bypassing PackageManager hooks (HMA, DenyList, Shamiko).
     *
     * Android 9+ layout:  /data/app/~~RANDOM==/PACKAGE-RANDOM==/
     * Android 7–8 layout: /data/app/PACKAGE-N/
     */
    private fun scanDataAppForPackages(vararg packages: String): List<String> {
        val found = mutableListOf<String>()
        try {
            val dataApp = File("/data/app")
            val outerEntries = dataApp.listFiles() ?: return found
            for (outer in outerEntries) {
                if (!outer.isDirectory) continue
                val outerName = outer.name
                // Android 7–8 flat layout
                for (pkg in packages) {
                    if (outerName == pkg || outerName.startsWith("$pkg-")) {
                        found.add(outer.path)
                    }
                }
                // Android 9+ double-encoded layout: outer dir is ~~RANDOM==
                if (outerName.startsWith("~~")) {
                    try {
                        val innerEntries = outer.listFiles() ?: continue
                        for (inner in innerEntries) {
                            if (!inner.isDirectory) continue
                            for (pkg in packages) {
                                if (inner.name == pkg || inner.name.startsWith("$pkg-")) {
                                    found.add(inner.path)
                                }
                            }
                        }
                    } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {}
        return found
    }

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
