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
        // Top Connection Pill & Refresh
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
                    text = if (connectionState == ConnectionStatus.CONNECTED) "${repository.host}:${repository.port}" else "Disconnected",
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

        Spacer(modifier = Modifier.height(16.dp))

        // Main Security Status Banner
        val health = status?.healthState ?: "UNKNOWN"
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
                    text = status?.hostname ?: "Local Host",
                    fontSize = 13.sp,
                    color = TextSecondary
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

        val currentLevel = status?.protectionLevel ?: "balanced"
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
                                    repository.setProtectionLevel(level)
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
                value = status?.stats?.totalIncidents?.toString() ?: "0",
                icon = Icons.Default.NotificationsActive,
                modifier = Modifier.weight(1f)
            )
            MetricCard(
                title = "Containment Actions",
                value = status?.stats?.totalActions?.toString() ?: "0",
                icon = Icons.Default.Gavel,
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Incidents by Band Breakdown
        status?.stats?.incidentsByBand?.let { bands ->
            Text(
                text = "THREAT LEVEL BREAKDOWN",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = TextSecondary,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            Card(
                colors = CardDefaults.cardColors(containerColor = DarkSurface),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, BorderColor, RoundedCornerShape(12.dp))
                    .clickable { onNavigateToAlerts() }
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceAround
                ) {
                    BandCountItem("RED", bands["RED"] ?: 0, BandRed)
                    BandCountItem("ORANGE", bands["ORANGE"] ?: 0, BandOrange)
                    BandCountItem("YELLOW", bands["YELLOW"] ?: 0, BandYellow)
                    BandCountItem("GREEN", bands["GREEN"] ?: 0, BandGreen)
                }
            }
        }
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

@Composable
fun BandCountItem(label: String, count: Int, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(text = count.toString(), fontSize = 18.sp, fontWeight = FontWeight.Bold, color = color)
        Text(text = label, fontSize = 10.sp, color = TextSecondary, fontWeight = FontWeight.Medium)
    }
}
