package com.anycheck.app.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.anycheck.app.detection.DetectionCategory
import com.anycheck.app.detection.DetectionResult
import com.anycheck.app.detection.DetectionStatus
import com.anycheck.app.detection.RiskLevel
import com.anycheck.app.ui.theme.RiskCritical
import com.anycheck.app.ui.theme.RiskCriticalContainer
import com.anycheck.app.ui.theme.RiskHigh
import com.anycheck.app.ui.theme.RiskHighContainer
import com.anycheck.app.ui.theme.RiskInfo
import com.anycheck.app.ui.theme.RiskInfoContainer
import com.anycheck.app.ui.theme.RiskLow
import com.anycheck.app.ui.theme.RiskLowContainer
import com.anycheck.app.ui.theme.RiskMedium
import com.anycheck.app.ui.theme.RiskMediumContainer
import com.anycheck.app.ui.theme.StatusDetected
import com.anycheck.app.ui.theme.StatusError
import com.anycheck.app.ui.theme.StatusNotDetected

@Composable
fun DetectionResultCard(
    result: DetectionResult,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(result.status == DetectionStatus.DETECTED) }

    val (riskColor, riskContainerColor) = riskColors(result.riskLevel)
    val (statusColor, statusIcon) = statusStyle(result.status)
    val cardContainerColor = when (result.status) {
        DetectionStatus.DETECTED -> riskContainerColor
        DetectionStatus.NOT_DETECTED -> MaterialTheme.colorScheme.surfaceContainerLow
        DetectionStatus.ERROR -> MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .animateContentSize()
            .clickable { expanded = !expanded },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = cardContainerColor
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = if (result.status == DetectionStatus.DETECTED) 2.dp else 0.dp
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Status icon
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(statusColor.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = statusIcon,
                        contentDescription = result.status.name,
                        tint = statusColor,
                        modifier = Modifier.size(22.dp)
                    )
                }

                // Name and category
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = result.name,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = if (result.status == DetectionStatus.DETECTED) FontWeight.Bold else FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CategoryBadge(category = result.category)
                        RiskBadge(riskLevel = result.riskLevel, color = riskColor)
                    }
                }

                // Expand/collapse icon
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = if (expanded) "Collapse" else "Expand",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp)
                )
            }

            // Brief description always visible
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = result.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // Expanded details
            AnimatedVisibility(
                visible = expanded,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column {
                    Spacer(modifier = Modifier.height(12.dp))
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    // Detailed reason
                    DetailSection(
                        icon = Icons.Default.Info,
                        title = "Reason",
                        content = result.detailedReason,
                        iconTint = MaterialTheme.colorScheme.primary
                    )

                    if (result.status == DetectionStatus.DETECTED) {
                        Spacer(modifier = Modifier.height(10.dp))
                        // Solution
                        DetailSection(
                            icon = Icons.AutoMirrored.Filled.HelpOutline,
                            title = "Solution",
                            content = result.solution,
                            iconTint = RiskLow
                        )
                    }

                    if (result.technicalDetail.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        // Technical details
                        TechnicalDetailBox(detail = result.technicalDetail)
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailSection(
    icon: ImageVector,
    title: String,
    content: String,
    iconTint: Color,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = icon,
            contentDescription = title,
            tint = iconTint,
            modifier = Modifier
                .size(16.dp)
                .padding(top = 2.dp)
        )
        Column {
            Text(
                text = title,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = content,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 18.sp
            )
        }
    }
}

@Composable
private fun TechnicalDetailBox(detail: String, modifier: Modifier = Modifier) {
    Column(modifier = modifier) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.BugReport,
                contentDescription = "Technical Details",
                tint = MaterialTheme.colorScheme.outline,
                modifier = Modifier.size(16.dp)
            )
            Text(
                text = "Technical Details",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Surface(
            shape = RoundedCornerShape(8.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = 0.7f),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp)
            )
        }
    }
}

@Composable
fun CategoryBadge(category: DetectionCategory, modifier: Modifier = Modifier) {
    val (text, color) = when (category) {
        DetectionCategory.MAGISK -> "Magisk" to Color(0xFF4A55A2)
        DetectionCategory.KERNELSU -> "KernelSU" to Color(0xFF00796B)
        DetectionCategory.APATCH -> "APatch" to Color(0xFF6A1B9A)
        DetectionCategory.SU_BINARY -> "SU Binary" to Color(0xFFE65100)
        DetectionCategory.ROOT_MANAGEMENT -> "Root" to Color(0xFF37474F)
    }
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = color.copy(alpha = 0.15f),
        modifier = modifier
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@Composable
fun RiskBadge(riskLevel: RiskLevel, color: Color, modifier: Modifier = Modifier) {
    val text = when (riskLevel) {
        RiskLevel.CRITICAL -> "Critical"
        RiskLevel.HIGH -> "High"
        RiskLevel.MEDIUM -> "Medium"
        RiskLevel.LOW -> "Low"
        RiskLevel.INFO -> "Info"
    }
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = color.copy(alpha = 0.12f),
        modifier = modifier
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

fun riskColors(riskLevel: RiskLevel): Pair<Color, Color> = when (riskLevel) {
    RiskLevel.CRITICAL -> RiskCritical to RiskCriticalContainer
    RiskLevel.HIGH -> RiskHigh to RiskHighContainer
    RiskLevel.MEDIUM -> RiskMedium to RiskMediumContainer
    RiskLevel.LOW -> RiskLow to RiskLowContainer
    RiskLevel.INFO -> RiskInfo to RiskInfoContainer
}

fun statusStyle(status: DetectionStatus): Pair<Color, ImageVector> = when (status) {
    DetectionStatus.DETECTED -> StatusDetected to Icons.Default.Error
    DetectionStatus.NOT_DETECTED -> StatusNotDetected to Icons.Default.CheckCircle
    DetectionStatus.ERROR -> StatusError to Icons.Default.Warning
}
