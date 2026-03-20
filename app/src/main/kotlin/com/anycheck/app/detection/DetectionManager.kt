package com.anycheck.app.detection

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Orchestrates all detection engines and produces a unified DetectionSummary.
 */
class DetectionManager(private val context: Context) {

    suspend fun runFullDetection(
        onProgress: (Int, Int, String) -> Unit = { _, _, _ -> }
    ): DetectionSummary = withContext(Dispatchers.IO) {
        val allResults = mutableListOf<DetectionResult>()

        val magiskDetector = MagiskDetector(context)
        val kernelSUDetector = KernelSUDetector(context)
        val genericDetector = GenericRootDetector(context)

        val magiskChecks = magiskDetector.runAllChecks()
        onProgress(magiskChecks.size, 0, "Magisk checks complete")
        allResults.addAll(magiskChecks)

        val ksuChecks = kernelSUDetector.runAllChecks()
        onProgress(magiskChecks.size + ksuChecks.size, magiskChecks.size, "KernelSU checks complete")
        allResults.addAll(ksuChecks)

        val genericChecks = genericDetector.runAllChecks()
        onProgress(
            magiskChecks.size + ksuChecks.size + genericChecks.size,
            magiskChecks.size + ksuChecks.size,
            "Generic checks complete"
        )
        allResults.addAll(genericChecks)

        // Sort by: detected first, then by risk level, then by category
        val sorted = allResults.sortedWith(
            compareBy<DetectionResult> {
                when (it.status) {
                    DetectionStatus.DETECTED -> 0
                    DetectionStatus.ERROR -> 1
                    DetectionStatus.NOT_DETECTED -> 2
                }
            }.thenBy { it.riskLevel.order }
        )

        DetectionSummary(results = sorted)
    }
}
