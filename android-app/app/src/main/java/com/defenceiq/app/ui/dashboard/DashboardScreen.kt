package com.defenceiq.app.ui.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.defenceiq.app.network.ConnectionStatus
import com.defenceiq.app.network.DefenceIqRepository
import com.defenceiq.app.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun DashboardScreen(
    repository: DefenceIqRepository,
    onNavigateToAlerts: () -> Unit
) {
    val connectionState by repository.connectionState.collectAsState()
    val status by repository.agentStatus.collectAsState()
    val pairedDevice by repository.pairedDevice.collectAsState()
    val scrollState = rememberScrollState()
    val coroutineScope = rememberCoroutineScope()
    var isUpdatingLevel by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DarkBackground)
            .verticalScroll(scrollState)
            .padding(16.dp)
    ) {
        // Top Connection Banner
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .clip(RoundedCornerShape(20.dp))
                    .background(DarkSurface)
                    .border(1.dp, BorderColor, RoundedCornerShape(20.dp))
                    .padding(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(if (connectionState == ConnectionStatus.CONNECTED) NeonGreen else BandRed)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (connectionState == ConnectionStatus.CONNECTED) "Linked via E2E Relay" else "Offline / Disconnected",
                    fontSize = 12.sp,
                    color = TextPrimary,
                    fontWeight = FontWeight.Medium
                )
            }

            IconButton(
                onClick = {
                    coroutineScope.launch {
                        repository.refreshStatus()
                        repository.refreshIncidents()
                    }
                }
            ) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberBlue)
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Paired Device Information Card
        Card(
            colors = CardDefaults.cardColors(containerColor = DarkSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, BorderColor, RoundedCornerShape(14.dp))
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = pairedDevice?.hostname ?: (status?.hostname ?: "My Laptop"),
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextPrimary
                        )
                        Text(
                            text = "ID: ${pairedDevice?.deviceId ?: "LAPTOP-LINKED"}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = CyberBlue
                        )
                    }

                    OutlinedButton(
                        onClick = { repository.unpair() },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = BandRed),
                        modifier = Modifier.height(32.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 0.dp)
                    ) {
                        Text("Unpair", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Main Security Status Banner
        val health = status?.healthState ?: "SECURE"
        val (badgeColor, healthIcon) = when (health) {
            "SECURE" -> Pair(BandGreen, Icons.Default.Shield)
            "WARNING" -> Pair(BandYellow, Icons.Default.Warning)
            "ELEVATED_RISK" -> Pair(BandOrange, Icons.Default.CrisisAlert)
            "CRITICAL_THREAT" -> Pair(BandRed, Icons.Default.GppBad)
            else -> Pair(TextSecondary, Icons.Default.Shield)
        }

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, badgeColor.copy(alpha = 0.5f), RoundedCornerShape(16.dp)),
            colors = CardDefaults.cardColors(containerColor = DarkSurface)
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    imageVector = healthIcon,
                    contentDescription = null,
                    tint = badgeColor,
                    modifier = Modifier.size(56.dp)
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = health.replace("_", " "),
                    fontSize = 22.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = badgeColor,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "AI Threat Scorer & Process/File Watchers Active",
                    fontSize = 12.sp,
                    color = TextSecondary
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Authorized Monitoring Scope Card
        Card(
            colors = CardDefaults.cardColors(containerColor = DarkSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, BorderColor, RoundedCornerShape(14.dp))
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "AUTHORIZED MONITORING SCOPE",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = CyberBlue,
                        letterSpacing = 1.sp
                    )
                    Text(
                        text = "LEAST PRIVILEGE",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = NeonGreen
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                val paths = pairedDevice?.authorizedPaths?.ifEmpty { null }
                    ?: listOf("Downloads", "Desktop", "Documents", "Startup autorun keys")

                paths.take(4).forEach { p ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(vertical = 2.dp)
                    ) {
                        Icon(Icons.Default.CheckCircle, contentDescription = null, tint = NeonGreen, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(text = p.substringAfterLast("\\").ifEmpty { p }, fontSize = 12.sp, color = TextPrimary)
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Zero Content Transmission: Telemetry strictly monitors process metadata, hashes & entropy. File contents are never exposed.",
                    fontSize = 11.sp,
                    color = TextSecondary,
                    lineHeight = 15.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Protection Level Selector
        Text(
            text = "PROTECTION LEVEL",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = TextSecondary,
            letterSpacing = 1.sp
        )
        Spacer(modifier = Modifier.height(8.dp))

        val currentLevel = pairedDevice?.protectionLevel ?: (status?.protectionLevel ?: "balanced")
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            listOf("basic", "balanced", "maximum").forEach { level ->
                val isSelected = currentLevel.equals(level, ignoreCase = true)
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (isSelected) NeonGreen else DarkSurface
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .border(1.dp, if (isSelected) NeonGreen else BorderColor, RoundedCornerShape(10.dp))
                        .clickable(enabled = !isUpdatingLevel) {
                            if (!isSelected) {
                                isUpdatingLevel = true
                                coroutineScope.launch {
                                    repository.updateProtectionLevel(level)
                                    isUpdatingLevel = false
                                }
                            }
                        }
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 12.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = level.uppercase(),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (isSelected) DarkBackground else TextPrimary
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Telemetry Metrics Grid
        Text(
            text = "SYSTEM TELEMETRY",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = TextSecondary,
            letterSpacing = 1.sp
        )
        Spacer(modifier = Modifier.height(8.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            MetricCard(
                title = "Monitored PIDs",
                value = status?.monitoredPidsCount?.toString() ?: "0",
                icon = Icons.Default.Memory,
                modifier = Modifier.weight(1f)
            )
            MetricCard(
                title = "Active Sockets",
                value = status?.activeSocketsCount?.toString() ?: "0",
                icon = Icons.Default.Language,
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            MetricCard(
                title = "Incidents",
                value = repository.incidents.collectAsState().value.size.toString(),
                icon = Icons.Default.NotificationsActive,
                modifier = Modifier.weight(1f).clickable { onNavigateToAlerts() }
            )
            MetricCard(
                title = "Actions Taken",
                value = status?.stats?.totalActions?.toString() ?: "0",
                icon = Icons.Default.Gavel,
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(20.dp))
    }
}

@Composable
fun MetricCard(
    title: String,
    value: String,
    icon: ImageVector,
    modifier: Modifier = Modifier
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        modifier = modifier.border(1.dp, BorderColor, RoundedCornerShape(12.dp))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Icon(icon, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.height(8.dp))
            Text(text = value, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            Text(text = title, fontSize = 11.sp, color = TextSecondary)
        }
    }
}
