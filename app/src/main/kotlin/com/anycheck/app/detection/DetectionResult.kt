package com.anycheck.app.detection

/**
 * Represents a single detection check result.
 */
data class DetectionResult(
    val id: String,
    val name: String,
    val category: DetectionCategory,
    val status: DetectionStatus,
    val riskLevel: RiskLevel,
    val description: String,
    val detailedReason: String,
    val solution: String,
    val technicalDetail: String = ""
)

enum class DetectionStatus {
    DETECTED,       // Evidence found - indicates root framework is present
    NOT_DETECTED,   // No evidence found
    ERROR           // Could not complete the check
}

enum class RiskLevel(val order: Int) {
    CRITICAL(0),
    HIGH(1),
    MEDIUM(2),
    LOW(3),
    INFO(4)
}

enum class DetectionCategory {
    MAGISK,
    KERNELSU,
    APATCH,
    SU_BINARY,
    ROOT_MANAGEMENT,
    XPOSED,
    SYSTEM_INTEGRITY,
    ADB_DEBUG,
    FRIDA,
    ENVIRONMENT
}

/**
 * Aggregated summary of all detection results.
 */
data class DetectionSummary(
    val results: List<DetectionResult>,
    val detectedCount: Int = results.count { it.status == DetectionStatus.DETECTED },
    val safeCount: Int = results.count { it.status == DetectionStatus.NOT_DETECTED },
    val errorCount: Int = results.count { it.status == DetectionStatus.ERROR },
    val hasMagisk: Boolean = results.any {
        it.category == DetectionCategory.MAGISK && it.status == DetectionStatus.DETECTED
    },
    val hasKernelSU: Boolean = results.any {
        it.category == DetectionCategory.KERNELSU && it.status == DetectionStatus.DETECTED
    },
    val hasAPatch: Boolean = results.any {
        it.category == DetectionCategory.APATCH && it.status == DetectionStatus.DETECTED
    },
    val hasSuBinary: Boolean = results.any {
        it.category == DetectionCategory.SU_BINARY && it.status == DetectionStatus.DETECTED
    }
)
