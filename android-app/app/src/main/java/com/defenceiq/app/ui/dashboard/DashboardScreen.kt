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
    val lastSeen by repository.lastSeen.collectAsState()
    val lastConnected by repository.lastConnected.collectAsState()
    val securityAlerts by repository.securityAlerts.collectAsState()

    val scrollState = rememberScrollState()
    val coroutineScope = rememberCoroutineScope()
    var isUpdatingLevel by remember { mutableStateOf(false) }
    var showUnpairConfirmDialog by remember { mutableStateOf(false) }

    val sysMetrics = status?.systemMetrics
    val activeWin = status?.activeWindow

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(LightBackground)
            .verticalScroll(scrollState)
            .padding(16.dp)
    ) {
        // Top Connection & Header Bar
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "DefenceIQ",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = TextPrimary
                )
                Text(
                    text = "Endpoint Protection & Live Monitoring",
                    fontSize = 12.sp,
                    color = TextSecondary
                )
            }

            IconButton(
                onClick = {
                    coroutineScope.launch {
                        repository.tryLocalAutoConnect()
                        repository.refreshStatus()
                        repository.refreshIncidents()
                        repository.refreshSecurityAlerts()
                    }
                }
            ) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = PrimaryBlue)
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // =========================================================================
        // 1. CONNECTION DASHBOARD CARD (Requirements #1, #7, #6)
        // =========================================================================
        val (statusColor, statusBg, statusIcon, statusText) = when (connectionState) {
            ConnectionStatus.CONNECTED -> Quadruple(
                BandGreen,
                BandGreen.copy(alpha = 0.1f),
                Icons.Default.CheckCircle,
                "Connected"
            )
            ConnectionStatus.CONNECTING -> Quadruple(
                BandYellow,
                BandYellow.copy(alpha = 0.1f),
                Icons.Default.Sync,
                "Connecting"
            )
            ConnectionStatus.CONNECTION_LOST -> Quadruple(
                BandOrange,
                BandOrange.copy(alpha = 0.1f),
                Icons.Default.WifiOff,
                "Connection Lost"
            )
            ConnectionStatus.LAPTOP_OFFLINE -> Quadruple(
                BandRed,
                BandRed.copy(alpha = 0.1f),
                Icons.Default.PowerSettingsNew,
                "Laptop Offline"
            )
            ConnectionStatus.DISCONNECTED -> Quadruple(
                TextSecondary,
                LightSurfaceVariant,
                Icons.Default.LinkOff,
                "Disconnected"
            )
        }

        val deviceName = status?.hostname?.ifEmpty { null }
            ?: (pairedDevice?.hostname?.ifEmpty { null } ?: "Host Laptop")
        val deviceType = status?.deviceType ?: "Windows Workstation"
        val lanIp = status?.lanIp?.ifEmpty { null }
            ?: (pairedDevice?.isCloudRelay?.let { if (it) "Cloud Relay (Global)" else "Local Wi-Fi" } ?: "127.0.0.1")

        Card(
            colors = CardDefaults.cardColors(containerColor = LightSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                // Header with Laptop Icon, Name, and Status Badge
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(42.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(LightSurfaceVariant),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Laptop,
                                contentDescription = "Laptop",
                                tint = PrimaryBlue,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = deviceName,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary
                            )
                            Text(
                                text = deviceType,
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }
                    }

                    // Real-Time Live Status Pill
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .clip(RoundedCornerShape(20.dp))
                            .background(statusBg)
                            .border(1.dp, statusColor.copy(alpha = 0.3f), RoundedCornerShape(20.dp))
                            .padding(horizontal = 10.dp, vertical = 5.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(7.dp)
                                .clip(CircleShape)
                                .background(statusColor)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Icon(
                            imageVector = statusIcon,
                            contentDescription = null,
                            tint = statusColor,
                            modifier = Modifier.size(13.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = statusText,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = statusColor
                        )
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))
                Divider(color = LightBorderColor)
                Spacer(modifier = Modifier.height(12.dp))

                // Network and Timing Metadata Grid
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Lan, contentDescription = null, tint = TextMuted, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(text = "Network / IP", fontSize = 11.sp, color = TextSecondary)
                        }
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = lanIp,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                            fontFamily = FontFamily.Monospace,
                            color = TextPrimary
                        )
                    }

                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.AccessTime, contentDescription = null, tint = TextMuted, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(text = "Last Seen", fontSize = 11.sp, color = TextSecondary)
                        }
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = lastSeen.ifEmpty { "Active Now" },
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                            fontFamily = FontFamily.Monospace,
                            color = if (connectionState == ConnectionStatus.CONNECTED) BandGreen else BandOrange
                        )
                    }
                }

                if (connectionState != ConnectionStatus.CONNECTED && lastConnected.isNotEmpty() && lastConnected != "Never") {
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.History, contentDescription = null, tint = TextMuted, modifier = Modifier.size(13.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "Last Connected: $lastConnected",
                            fontSize = 11.sp,
                            color = TextMuted
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Unpair / Revoke Action
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    OutlinedButton(
                        onClick = { showUnpairConfirmDialog = true },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = BandRed),
                        modifier = Modifier.height(32.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 0.dp)
                    ) {
                        Icon(Icons.Default.LinkOff, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Revoke / Unpair", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        // Unpair Confirmation Dialog
        if (showUnpairConfirmDialog) {
            AlertDialog(
                onDismissRequest = { showUnpairConfirmDialog = false },
                title = { Text("Unpair Laptop?", fontWeight = FontWeight.Bold) },
                text = { Text("Are you sure you want to revoke pairing with $deviceName? You will need to enter a fresh pairing token to reconnect.") },
                confirmButton = {
                    Button(
                        onClick = {
                            showUnpairConfirmDialog = false
                            repository.revokePairing()
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = BandRed)
                    ) {
                        Text("Unpair Device")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showUnpairConfirmDialog = false }) {
                        Text("Cancel")
                    }
                }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // =========================================================================
        // 2. AUTOMATIC SECURITY ALERTS SUMMARY (Requirement #2)
        // =========================================================================
        val recentSecurityAlert = securityAlerts.firstOrNull()
        Card(
            colors = CardDefaults.cardColors(containerColor = LightSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
                .clickable { onNavigateToAlerts() }
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = PrimaryBlue,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "SECURITY EVENT MONITOR",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = PrimaryBlue,
                            letterSpacing = 0.5.sp
                        )
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(10.dp))
                            .background(LightSurfaceVariant)
                            .padding(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "${securityAlerts.size} Alerts",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextPrimary
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                if (recentSecurityAlert != null) {
                    val alertSeverityColor = when (recentSecurityAlert.severity) {
                        "CRITICAL" -> BandRed
                        "WARNING" -> BandYellow
                        else -> PrimaryBlue
                    }

                    Row(
                        verticalAlignment = Alignment.Top,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Box(
                            modifier = Modifier
                                .padding(top = 2.dp)
                                .size(8.dp)
                                .clip(CircleShape)
                                .background(alertSeverityColor)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = recentSecurityAlert.eventType.replace('_', ' '),
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary
                            )
                            Text(
                                text = recentSecurityAlert.details,
                                fontSize = 11.sp,
                                color = TextSecondary,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "${recentSecurityAlert.timestamp} • Status: ${recentSecurityAlert.connectionStatus}",
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = TextMuted
                            )
                        }
                    }
                } else {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CheckCircle, contentDescription = null, tint = BandGreen, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "No unauthorized connection attempts or unexpected disconnects detected.",
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // =========================================================================
        // 3. MAIN ENDPOINT HEALTH STATE BANNER
        // =========================================================================
        val health = status?.healthState ?: "SECURE"
        val (badgeColor, healthIcon) = when (health) {
            "SECURE" -> Pair(BandGreen, Icons.Default.Security)
            "WARNING" -> Pair(BandYellow, Icons.Default.Warning)
            "ELEVATED_RISK" -> Pair(BandOrange, Icons.Default.Warning)
            "CRITICAL_THREAT" -> Pair(BandRed, Icons.Default.Error)
            else -> Pair(TextSecondary, Icons.Default.Security)
        }

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, badgeColor.copy(alpha = 0.3f), RoundedCornerShape(14.dp)),
            colors = CardDefaults.cardColors(containerColor = LightSurface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    imageVector = healthIcon,
                    contentDescription = null,
                    tint = badgeColor,
                    modifier = Modifier.size(46.dp)
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = health.replace("_", " "),
                    fontSize = 20.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = badgeColor,
                    letterSpacing = 0.5.sp
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = "Autonomous AI Threat Scorer & Process/File Watchers Active",
                    fontSize = 11.sp,
                    color = TextSecondary
                )
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // =========================================================================
        // 4. PROTECTION LEVEL SELECTOR
        // =========================================================================
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
                        containerColor = if (isSelected) PrimaryBlue else LightSurface
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .border(
                            1.dp,
                            if (isSelected) PrimaryBlue else LightBorderColor,
                            RoundedCornerShape(10.dp)
                        )
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
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = level.uppercase(),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (isSelected) Color.White else TextPrimary
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // =========================================================================
        // 5. HARDWARE GAUGES (CPU, RAM, Storage, Battery)
        // =========================================================================
        Text(
            text = "HARDWARE GAUGES",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = TextSecondary,
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
                icon = Icons.Default.Memory,
                iconTint = PrimaryBlue,
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
                icon = Icons.Default.Storage,
                iconTint = BandGreen,
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
                title = "STORAGE",
                percent = diskPercent,
                valueText = "${diskPercent}%",
                icon = Icons.Default.SdStorage,
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
            val battTime = sysMetrics?.battery?.timeLeft ?: "AC Power"

            HardwareGaugeCard(
                title = "BATTERY",
                percent = battPercent,
                valueText = "${battPercent.toInt()}%",
                icon = if (isPlugged) Icons.Default.BatteryChargingFull else Icons.Default.BatteryFull,
                iconTint = if (isPlugged) BandGreen else BandYellow,
                details = listOf(
                    "Status" to if (isPlugged) "Plugged In" else "On Battery",
                    "Health" to battHealth,
                    "Time" to battTime
                ),
                modifier = Modifier.weight(1f),
                isBattery = true
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // =========================================================================
        // 6. NETWORK & INTERNET SPEEDS
        // =========================================================================
        Text(
            text = "NETWORK ACTIVITY",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = TextSecondary,
            letterSpacing = 1.sp
        )
        Spacer(modifier = Modifier.height(8.dp))

        val net = sysMetrics?.network ?: NetworkMetrics()
        Card(
            colors = CardDefaults.cardColors(containerColor = LightSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
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
                                .background(if (net.internetConnected) BandGreen else BandRed)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = if (net.internetConnected) "Internet Connected" else "No Route",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = if (net.internetConnected) BandGreen else BandRed
                        )
                    }

                    Text(
                        text = "Status: ${net.status}",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TextSecondary
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Download, contentDescription = null, tint = BandGreen, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "${net.downloadSpeedKbps} KB/s",
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(text = "Download Speed", fontSize = 10.sp, color = TextSecondary)
                        }
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Upload, contentDescription = null, tint = PrimaryBlue, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "${net.uploadSpeedKbps} KB/s",
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(text = "Upload Speed", fontSize = 10.sp, color = TextSecondary)
                        }
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))
                Divider(color = LightBorderColor)
                Spacer(modifier = Modifier.height(8.dp))

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

        Spacer(modifier = Modifier.height(16.dp))

        // =========================================================================
        // 7. ACTIVE APPLICATION GLANCE
        // =========================================================================
        if (activeWin != null && (!activeWin.appName.isNullOrEmpty() || !activeWin.windowTitle.isNullOrEmpty())) {
            Text(
                text = "ACTIVE DESKTOP APPLICATION",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = TextSecondary,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            Card(
                colors = CardDefaults.cardColors(containerColor = LightSurface),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Laptop, contentDescription = null, tint = PrimaryBlue, modifier = Modifier.size(16.dp))
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
                                text = "${activeWin.durationSeconds}s",
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                color = TextSecondary
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(6.dp))

                    Text(
                        text = activeWin.tabTitle ?: activeWin.windowTitle ?: "--",
                        fontSize = 12.sp,
                        color = TextPrimary,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }

        // =========================================================================
        // 8. TOP RUNNING APPLICATIONS
        // =========================================================================
        val topProcesses = sysMetrics?.topProcesses ?: emptyList()
        if (topProcesses.isNotEmpty()) {
            Text(
                text = "TOP RUNNING APPLICATIONS",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = TextSecondary,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            Card(
                colors = CardDefaults.cardColors(containerColor = LightSurface),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
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
                                .padding(vertical = 4.dp),
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
                                    color = PrimaryBlue
                                )
                            }
                        }
                        if (proc != topProcesses.take(6).last()) {
                            Divider(color = LightBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 2.dp))
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
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
            else -> BandGreen
        }
    } else {
        when {
            percent > 85.0 -> BandRed
            percent > 70.0 -> BandYellow
            else -> iconTint
        }
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = LightSurface),
        modifier = modifier.border(1.dp, LightBorderColor, RoundedCornerShape(12.dp))
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
                fontSize = 20.sp,
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
                trackColor = LightSurfaceVariant
            )

            Spacer(modifier = Modifier.height(8.dp))

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

data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
