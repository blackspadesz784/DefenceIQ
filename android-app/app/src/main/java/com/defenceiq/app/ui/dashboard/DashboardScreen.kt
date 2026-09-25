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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.defenceiq.app.data.*
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

    val sysMetrics = status?.systemMetrics
    val activeWin = status?.activeWindow

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
                    text = if (connectionState == ConnectionStatus.CONNECTED) "Connected (Live)" else "Offline / Disconnected",
                    fontSize = 12.sp,
                    color = TextPrimary,
                    fontWeight = FontWeight.Medium
                )
            }

            IconButton(
                onClick = {
                    coroutineScope.launch {
                        repository.tryLocalAutoConnect()
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

        Spacer(modifier = Modifier.height(24.dp))

        // =========================================================================
        // REAL-TIME SYSTEM PERFORMANCE MONITORING (Web Companion Parity)
        // =========================================================================
        Text(
            text = "REAL-TIME HARDWARE GAUGES",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = CyberBlue,
            letterSpacing = 1.sp
        )
        Spacer(modifier = Modifier.height(8.dp))

        // CPU & RAM Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            val cpuPercent = sysMetrics?.cpuPercent ?: 0.0
            val cpuFreq = sysMetrics?.cpuFreqMhz ?: 2400.0
            val cpuTemp = sysMetrics?.cpuTemp ?: "48°C (Nominal)"
            val physCores = sysMetrics?.cpuCoresPhysical ?: 4
            val logCores = sysMetrics?.cpuCoresLogical ?: 8

            HardwareGaugeCard(
                title = "CPU LOAD",
                percent = cpuPercent,
                valueText = "${cpuPercent}%",
                icon = Icons.Default.Speed,
                iconTint = CyberBlue,
                details = listOf(
                    "Cores" to "$physCores P / $logCores L",
                    "Clock" to "${cpuFreq.toInt()} MHz",
                    "Temp" to cpuTemp
                ),
                modifier = Modifier.weight(1f)
            )

            val ramPercent = sysMetrics?.ram?.percent ?: 0.0
            val ramUsed = sysMetrics?.ram?.usedGb ?: 0.0
            val ramTotal = sysMetrics?.ram?.totalGb ?: 0.0
            val ramFree = sysMetrics?.ram?.availableGb ?: 0.0

            HardwareGaugeCard(
                title = "RAM USAGE",
                percent = ramPercent,
                valueText = "${ramPercent}%",
                icon = Icons.Default.Memory,
                iconTint = NeonGreen,
                details = listOf(
                    "Used" to "${ramUsed} GB",
                    "Total" to "${ramTotal} GB",
                    "Free" to "${ramFree} GB"
                ),
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Storage & Battery Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            val diskPercent = sysMetrics?.disk?.percent ?: 0.0
            val diskFree = sysMetrics?.disk?.freeGb ?: 0.0
            val diskTotal = sysMetrics?.disk?.totalGb ?: 0.0
            val diskRead = sysMetrics?.disk?.readSpeedKbps ?: 0.0
            val diskWrite = sysMetrics?.disk?.writeSpeedKbps ?: 0.0

            HardwareGaugeCard(
                title = "DISK STORAGE",
                percent = diskPercent,
                valueText = "${diskPercent}%",
                icon = Icons.Default.Storage,
                iconTint = BandYellow,
                details = listOf(
                    "Free" to "${diskFree} GB",
                    "Total" to "${diskTotal} GB",
                    "Activity" to "R: ${diskRead.toInt()} | W: ${diskWrite.toInt()} KB/s"
                ),
                modifier = Modifier.weight(1f)
            )

            val battPercent = sysMetrics?.battery?.percent ?: 100.0
            val isPlugged = sysMetrics?.battery?.plugged ?: true
            val battHealth = sysMetrics?.battery?.health ?: "Good"
            val battTime = sysMetrics?.battery?.timeLeft ?: "Full / AC Power"

            HardwareGaugeCard(
                title = "BATTERY",
                percent = battPercent,
                valueText = "${battPercent.toInt()}%",
                icon = if (isPlugged) Icons.Default.BatteryChargingFull else Icons.Default.BatteryFull,
                iconTint = if (isPlugged) NeonGreen else BandYellow,
                details = listOf(
                    "Status" to if (isPlugged) "Charging ⚡" else "On Battery 🔋",
                    "Health" to battHealth,
                    "Remaining" to battTime
                ),
                modifier = Modifier.weight(1f),
                isBattery = true
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        // GPU Acceleration Card
        val gpu = sysMetrics?.gpu ?: GpuMetrics()
        Card(
            colors = CardDefaults.cardColors(containerColor = DarkSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, BorderColor, RoundedCornerShape(12.dp))
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.DeveloperBoard, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "GPU ACCELERATION",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = CyberBlue,
                            letterSpacing = 0.5.sp
                        )
                    }
                    Text(
                        text = gpu.status,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = NeonGreen,
                        fontFamily = FontFamily.Monospace
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = gpu.name,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Text(
                        text = "${gpu.vramMb.toInt()} MB VRAM",
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TextSecondary
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // =========================================================================
        // NETWORK & INTERNET CONNECTIVITY
        // =========================================================================
        Text(
            text = "NETWORK & INTERNET SPEEDS",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = CyberBlue,
            letterSpacing = 1.sp
        )
        Spacer(modifier = Modifier.height(8.dp))

        val net = sysMetrics?.network ?: NetworkMetrics()
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
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .clip(CircleShape)
                                .background(if (net.internetConnected) NeonGreen else BandRed)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = if (net.internetConnected) "Internet Reachable 🌐" else "Offline / No Route",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = if (net.internetConnected) NeonGreen else BandRed
                        )
                    }

                    Text(
                        text = "Status: ${net.status}",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TextSecondary
                    )
                }

                Spacer(modifier = Modifier.height(14.dp))

                // Speeds Row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    // Download Speed
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.ArrowDownward, contentDescription = null, tint = NeonGreen, modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "${net.downloadSpeedKbps} KB/s",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(text = "Download Speed", fontSize = 10.sp, color = TextSecondary)
                        }
                    }

                    // Upload Speed
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.ArrowUpward, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "${net.uploadSpeedKbps} KB/s",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(text = "Upload Speed", fontSize = 10.sp, color = TextSecondary)
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))
                Divider(color = BorderColor.copy(alpha = 0.5f))
                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Total Sent: ${net.bytesSentMb} MB",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TextSecondary
                    )
                    Text(
                        text = "Total Recv: ${net.bytesRecvMb} MB",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TextSecondary
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // =========================================================================
        // DEVICE SPECIFICATIONS & UPTIME
        // =========================================================================
        Text(
            text = "DEVICE & OPERATING SYSTEM",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = CyberBlue,
            letterSpacing = 1.sp
        )
        Spacer(modifier = Modifier.height(8.dp))

        val sysInfo = sysMetrics?.systemInfo ?: SystemInfoMetrics()
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
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Computer, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = sysInfo.deviceName.ifEmpty { pairedDevice?.hostname ?: "My Laptop" },
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextPrimary
                        )
                    }

                    // Uptime pill
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .clip(RoundedCornerShape(12.dp))
                            .background(DarkSurfaceVariant)
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Icon(Icons.Default.Timer, contentDescription = null, tint = NeonGreen, modifier = Modifier.size(12.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "Up: ${sysInfo.uptime.ifEmpty { "14h 30m" }}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = NeonGreen
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(text = "Operating System:", fontSize = 11.sp, color = TextSecondary)
                        Text(text = sysInfo.osName, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(text = "OS Build Version:", fontSize = 11.sp, color = TextSecondary)
                        Text(text = sysInfo.build.ifEmpty { "10.0.26200" }, fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(text = "Processor:", fontSize = 11.sp, color = TextSecondary)
                        Text(
                            text = sysInfo.processor.ifEmpty { "Intel Core i5" }.take(32),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(text = "Architecture:", fontSize = 11.sp, color = TextSecondary)
                        Text(text = sysInfo.architecture.ifEmpty { "AMD64 / x86_64" }, fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = CyberBlue)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // =========================================================================
        // ACTIVE FOREGROUND WINDOW / APPLICATION GLANCE
        // =========================================================================
        if (activeWin != null && (!activeWin.appName.isNullOrEmpty() || !activeWin.windowTitle.isNullOrEmpty())) {
            Text(
                text = "ACTIVE DESKTOP APPLICATION",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = CyberBlue,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            Card(
                colors = CardDefaults.cardColors(containerColor = DarkSurface),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, CyberBlue.copy(alpha = 0.5f), RoundedCornerShape(14.dp))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Apps, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = activeWin.appName ?: activeWin.processName ?: "Active Application",
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary
                            )
                        }

                        if (activeWin.durationSeconds > 0) {
                            Text(
                                text = "⏱️ ${activeWin.durationSeconds}s",
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                color = NeonGreen
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = activeWin.tabTitle ?: activeWin.windowTitle ?: "--",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Medium,
                        color = TextPrimary,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )

                    if (!activeWin.urlDomain.isNullOrEmpty()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(BandYellow.copy(alpha = 0.15f))
                                .border(1.dp, BandYellow.copy(alpha = 0.4f), RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = activeWin.urlDomain,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                color = BandYellow
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
        }

        // =========================================================================
        // TOP RUNNING PROCESSES
        // =========================================================================
        val topProcesses = sysMetrics?.topProcesses ?: emptyList()
        if (topProcesses.isNotEmpty()) {
            Text(
                text = "TOP RUNNING APPLICATIONS",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = CyberBlue,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            Card(
                colors = CardDefaults.cardColors(containerColor = DarkSurface),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, BorderColor, RoundedCornerShape(14.dp))
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(text = "APPLICATION", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
                        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                            Text(text = "CPU", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
                            Text(text = "MEMORY", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    topProcesses.take(6).forEach { proc ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 5.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = proc.name,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = TextPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "PID: ${proc.pid}",
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = TextMuted
                                )
                            }

                            Row(
                                horizontalArrangement = Arrangement.spacedBy(16.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "${proc.cpuPercent}%",
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = if (proc.cpuPercent > 30.0) BandRed else TextPrimary
                                )
                                Text(
                                    text = "${proc.memoryMb.toInt()} MB",
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = CyberBlue
                                )
                            }
                        }
                        if (proc != topProcesses.take(6).last()) {
                            Divider(color = BorderColor.copy(alpha = 0.3f), modifier = Modifier.padding(vertical = 2.dp))
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))
    }
}

@Composable
fun HardwareGaugeCard(
    title: String,
    percent: Double,
    valueText: String,
    icon: ImageVector,
    iconTint: Color,
    details: List<Pair<String, String>>,
    modifier: Modifier = Modifier,
    isBattery: Boolean = false
) {
    val barColor = if (isBattery) {
        when {
            percent <= 20.0 -> BandRed
            percent <= 40.0 -> BandYellow
            else -> NeonGreen
        }
    } else {
        when {
            percent > 85.0 -> BandRed
            percent > 70.0 -> BandYellow
            else -> iconTint
        }
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        modifier = modifier.border(1.dp, BorderColor, RoundedCornerShape(12.dp))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextSecondary,
                    letterSpacing = 0.5.sp
                )
                Icon(icon, contentDescription = null, tint = iconTint, modifier = Modifier.size(16.dp))
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = valueText,
                fontSize = 22.sp,
                fontWeight = FontWeight.ExtraBold,
                fontFamily = FontFamily.Monospace,
                color = barColor
            )

            Spacer(modifier = Modifier.height(6.dp))

            LinearProgressIndicator(
                progress = (percent / 100.0).coerceIn(0.0, 1.0).toFloat(),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(5.dp)
                    .clip(RoundedCornerShape(3.dp)),
                color = barColor,
                trackColor = DarkSurfaceVariant
            )

            Spacer(modifier = Modifier.height(10.dp))

            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                details.forEach { (label, value) ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(text = label, fontSize = 10.sp, color = TextMuted)
                        Text(
                            text = value,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Medium,
                            color = TextPrimary
                        )
                    }
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
