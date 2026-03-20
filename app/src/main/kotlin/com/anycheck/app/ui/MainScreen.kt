package com.anycheck.app.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.ShieldMoon
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.anycheck.app.DetectionUiState
import com.anycheck.app.detection.DetectionCategory
import com.anycheck.app.detection.DetectionResult
import com.anycheck.app.detection.DetectionStatus
import com.anycheck.app.detection.DetectionSummary
import com.anycheck.app.detection.RiskLevel
import com.anycheck.app.ui.components.DetectionResultCard
import com.anycheck.app.ui.theme.RiskCritical
import com.anycheck.app.ui.theme.RiskLow
import kotlinx.coroutines.launch

enum class ResultFilter {
    ALL, DETECTED, MAGISK, KERNELSU, APATCH, SU, XPOSED
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    uiState: DetectionUiState,
    onStartDetection: () -> Unit,
    onReset: () -> Unit,
    modifier: Modifier = Modifier
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val clipboardManager = LocalClipboardManager.current

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Text(
                            text = "AnyCheck",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                    }
                },
                actions = {
                    if (uiState is DetectionUiState.Complete) {
                        IconButton(onClick = {
                            val text = buildReportText(uiState.summary)
                            clipboardManager.setText(AnnotatedString(text))
                            scope.launch { snackbarHostState.showSnackbar("Results copied to clipboard") }
                        }) {
                            Icon(Icons.Default.ContentCopy, contentDescription = "Copy results")
                        }
                        IconButton(onClick = onReset) {
                            Icon(Icons.Default.Refresh, contentDescription = "Reset")
                        }
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                )
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        modifier = modifier
    ) { paddingValues ->
        AnimatedContent(
            targetState = uiState,
            transitionSpec = { fadeIn() togetherWith fadeOut() },
            label = "screen_transition",
            modifier = Modifier.padding(paddingValues)
        ) { state ->
            when (state) {
                is DetectionUiState.Idle -> IdleScreen(onStartDetection = onStartDetection)
                is DetectionUiState.Running -> RunningScreen(progress = state.progress)
                is DetectionUiState.Complete -> ResultsScreen(
                    summary = state.summary,
                    onRedetect = {
                        onReset()
                        onStartDetection()
                    }
                )
                is DetectionUiState.Error -> ErrorScreen(
                    message = state.message,
                    onRetry = onStartDetection
                )
            }
        }
    }
}

@Composable
private fun IdleScreen(onStartDetection: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Security,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(80.dp)
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "Root Detection Analyzer",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Comprehensive detection of Magisk, KernelSU, APatch and other root frameworks using multiple detection vectors.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(16.dp))
        // Feature summary
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            FeatureRow("Magisk detection (12 checks)")
            FeatureRow("KernelSU detection (8 checks)")
            FeatureRow("APatch & generic root (5 checks)")
            FeatureRow("Xposed / LSPosed / EdXposed (8 checks)")
            FeatureRow("Advanced root checks (19 checks)")
            FeatureRow("Detailed reason & solution for each")
        }
        Spacer(modifier = Modifier.height(32.dp))
        Button(
            onClick = onStartDetection,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            Icon(Icons.Default.Search, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "Start Detection",
                style = MaterialTheme.typography.titleMedium
            )
        }
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = "For security research purposes only.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline
        )
    }
}

@Composable
private fun FeatureRow(text: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            imageVector = Icons.Default.Shield,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(16.dp)
        )
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun RunningScreen(progress: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(64.dp),
            strokeWidth = 4.dp
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "Detecting...",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Medium
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = progress,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun ErrorScreen(
    message: String,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Warning,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.error,
            modifier = Modifier.size(64.dp)
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "Detection Failed",
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.error
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onRetry) {
            Text("Retry")
        }
    }
}

@Composable
private fun ResultsScreen(
    summary: DetectionSummary,
    onRedetect: () -> Unit,
    modifier: Modifier = Modifier
) {
    var activeFilter by remember { mutableStateOf(ResultFilter.ALL) }

    val filteredResults = remember(activeFilter, summary.results) {
        when (activeFilter) {
            ResultFilter.ALL -> summary.results
            ResultFilter.DETECTED -> summary.results.filter { it.status == DetectionStatus.DETECTED }
            ResultFilter.MAGISK -> summary.results.filter { it.category == DetectionCategory.MAGISK }
            ResultFilter.KERNELSU -> summary.results.filter { it.category == DetectionCategory.KERNELSU }
            ResultFilter.APATCH -> summary.results.filter { it.category == DetectionCategory.APATCH }
            ResultFilter.SU -> summary.results.filter { it.category == DetectionCategory.SU_BINARY }
            ResultFilter.XPOSED -> summary.results.filter { it.category == DetectionCategory.XPOSED }
        }
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // Summary card
        item {
            SummaryCard(summary = summary, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
        }

        // Framework status row
        item {
            FrameworkStatusRow(
                summary = summary,
                modifier = Modifier.padding(horizontal = 16.dp)
            )
        }

        // Filter chips
        item {
            LazyRow(
                contentPadding = PaddingValues(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(ResultFilter.entries) { filter ->
                    val count = when (filter) {
                        ResultFilter.ALL -> summary.results.size
                        ResultFilter.DETECTED -> summary.detectedCount
                        ResultFilter.MAGISK -> summary.results.count { it.category == DetectionCategory.MAGISK }
                        ResultFilter.KERNELSU -> summary.results.count { it.category == DetectionCategory.KERNELSU }
                        ResultFilter.APATCH -> summary.results.count { it.category == DetectionCategory.APATCH }
                        ResultFilter.SU -> summary.results.count { it.category == DetectionCategory.SU_BINARY }
                        ResultFilter.XPOSED -> summary.results.count { it.category == DetectionCategory.XPOSED }
                    }
                    FilterChip(
                        selected = activeFilter == filter,
                        onClick = { activeFilter = filter },
                        label = {
                            Text(
                                text = when (filter) {
                                    ResultFilter.ALL -> "All ($count)"
                                    ResultFilter.DETECTED -> "Detected ($count)"
                                    ResultFilter.MAGISK -> "Magisk ($count)"
                                    ResultFilter.KERNELSU -> "KernelSU ($count)"
                                    ResultFilter.APATCH -> "APatch ($count)"
                                    ResultFilter.SU -> "SU Binary ($count)"
                                    ResultFilter.XPOSED -> "Xposed ($count)"
                                }
                            )
                        }
                    )
                }
            }
        }

        // Results
        items(filteredResults, key = { it.id }) { result ->
            DetectionResultCard(
                result = result,
                modifier = Modifier.padding(horizontal = 16.dp)
            )
        }

        // Re-detect button
        item {
            OutlinedButton(
                onClick = onRedetect,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .height(48.dp),
                shape = RoundedCornerShape(12.dp)
            ) {
                Icon(Icons.Default.Refresh, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Re-detect")
            }
        }
    }
}

@Composable
private fun SummaryCard(summary: DetectionSummary, modifier: Modifier = Modifier) {
    val overallSafe = summary.detectedCount == 0
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (overallSafe)
                MaterialTheme.colorScheme.primaryContainer
            else
                MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = if (overallSafe) Icons.Default.ShieldMoon else Icons.Default.Warning,
                    contentDescription = null,
                    tint = if (overallSafe) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(32.dp)
                )
                Column {
                    Text(
                        text = if (overallSafe) "Device Appears Clean" else "Root Framework Detected",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = if (overallSafe) MaterialTheme.colorScheme.onPrimaryContainer
                        else MaterialTheme.colorScheme.onErrorContainer
                    )
                    Text(
                        text = "Detection complete · ${summary.results.size} checks run",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (overallSafe) MaterialTheme.colorScheme.onPrimaryContainer.copy(0.7f)
                        else MaterialTheme.colorScheme.onErrorContainer.copy(0.7f)
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                SummaryStatItem(
                    count = summary.detectedCount,
                    label = "Detected",
                    color = if (summary.detectedCount > 0) RiskCritical else MaterialTheme.colorScheme.outline
                )
                SummaryStatItem(
                    count = summary.safeCount,
                    label = "Safe",
                    color = RiskLow
                )
                SummaryStatItem(
                    count = summary.errorCount,
                    label = "Errors",
                    color = MaterialTheme.colorScheme.outline
                )
            }
        }
    }
}

@Composable
private fun SummaryStatItem(count: Int, label: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = color
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun FrameworkStatusRow(summary: DetectionSummary, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        FrameworkStatusChip(
            name = "Magisk",
            detected = summary.hasMagisk,
            modifier = Modifier.weight(1f)
        )
        FrameworkStatusChip(
            name = "KernelSU",
            detected = summary.hasKernelSU,
            modifier = Modifier.weight(1f)
        )
        FrameworkStatusChip(
            name = "APatch",
            detected = summary.hasAPatch,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun FrameworkStatusChip(
    name: String,
    detected: Boolean,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = if (detected)
            MaterialTheme.colorScheme.errorContainer
        else
            MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = modifier
    ) {
        Column(
            modifier = Modifier.padding(10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = name,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = if (detected)
                    MaterialTheme.colorScheme.onErrorContainer
                else
                    MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = if (detected) "DETECTED" else "CLEAN",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = if (detected) RiskCritical else RiskLow
            )
        }
    }
}

private fun buildReportText(summary: DetectionSummary): String {
    val sb = StringBuilder()
    sb.appendLine("=== AnyCheck Detection Report ===")
    sb.appendLine()
    sb.appendLine("Summary:")
    sb.appendLine("  Total checks: ${summary.results.size}")
    sb.appendLine("  Detected: ${summary.detectedCount}")
    sb.appendLine("  Safe: ${summary.safeCount}")
    sb.appendLine("  Errors: ${summary.errorCount}")
    sb.appendLine()
    sb.appendLine("Framework Status:")
    sb.appendLine("  Magisk: ${if (summary.hasMagisk) "DETECTED" else "Not detected"}")
    sb.appendLine("  KernelSU: ${if (summary.hasKernelSU) "DETECTED" else "Not detected"}")
    sb.appendLine("  APatch: ${if (summary.hasAPatch) "DETECTED" else "Not detected"}")
    sb.appendLine()
    sb.appendLine("Detailed Results:")
    summary.results.forEach { result ->
        sb.appendLine()
        sb.appendLine("[${result.status.name}] ${result.name}")
        sb.appendLine("  Category: ${result.category.name}")
        sb.appendLine("  Risk: ${result.riskLevel.name}")
        sb.appendLine("  Description: ${result.description}")
        if (result.status == DetectionStatus.DETECTED) {
            sb.appendLine("  Reason: ${result.detailedReason}")
            sb.appendLine("  Solution: ${result.solution}")
        }
    }
    return sb.toString()
}
