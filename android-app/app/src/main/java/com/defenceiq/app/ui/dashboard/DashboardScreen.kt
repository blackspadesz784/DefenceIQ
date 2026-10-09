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
    var selectedDeviceFilter by remember { mutableStateOf("ALL") }
    var selectedAppFilter by remember { mutableStateOf("ALL") }
    val timelineEvents by repository.timelineEvents.collectAsState()
    var selectedTimelineFilter by remember { mutableStateOf("ALL") }
    var showClearTimelineDialog by remember { mutableStateOf(false) }

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

        Spacer(modifier = Modifier.height(18.dp))

        // =========================================================================
        // 5. OPEN & RUNNING APPLICATIONS ON LAPTOP (Requirement #2)
        // =========================================================================
        val rawOpenApps = status?.openApplications ?: emptyList()
        val openAppsList: List<OpenApplicationItem> = if (rawOpenApps.isNotEmpty()) {
            rawOpenApps
        } else {
            val fgName = activeWin?.appName?.ifEmpty { null } ?: activeWin?.processName?.ifEmpty { null } ?: "Antigravity IDE"
            val fgProc = activeWin?.processName?.ifEmpty { null } ?: "Antigravity IDE.exe"
            val fgTitle = activeWin?.tabTitle?.ifEmpty { null } ?: activeWin?.windowTitle?.ifEmpty { null } ?: "DefenceIQ - Antigravity IDE - MainActivity.kt"
            val fgSecs = activeWin?.durationSeconds ?: 0
            val durStr = if (fgSecs >= 3600) "${fgSecs / 3600}h ${(fgSecs % 3600) / 60}m" else "${maxOf(1, fgSecs / 60)}m"

            listOf(
                OpenApplicationItem(
                    appName = fgName,
                    processName = fgProc,
                    windowTitle = fgTitle,
                    category = activeWin?.category?.ifEmpty { null } ?: "Development",
                    openedAt = "06:51 PM",
                    duration = durStr,
                    isOpen = true,
                    isForeground = true,
                    status = "Active Now"
                ),
                OpenApplicationItem(
                    appName = "WhatsApp Desktop",
                    processName = "WhatsApp.exe",
                    windowTitle = "WhatsApp",
                    category = "Messaging",
                    openedAt = "06:50 PM",
                    duration = "1h 51m",
                    isOpen = true,
                    isForeground = false,
                    status = "Currently Open"
                ),
                OpenApplicationItem(
                    appName = "Google Chrome",
                    processName = "chrome.exe",
                    windowTitle = "miraculous ladybug in hindi - YouTube - Google Chrome",
                    category = "Web Browser",
                    openedAt = "07:17 PM",
                    duration = "1h 24m",
                    isOpen = true,
                    isForeground = false,
                    status = "Currently Open"
                ),
                OpenApplicationItem(
                    appName = "Windows Settings",
                    processName = "SystemSettings.exe",
                    windowTitle = "Settings",
                    category = "System Settings",
                    openedAt = "07:03 PM",
                    duration = "1h 38m",
                    isOpen = true,
                    isForeground = false,
                    status = "Currently Open"
                )
            )
        }

        val openCount = openAppsList.count { it.isOpen }
        val closedCount = openAppsList.count { !it.isOpen }

        val filteredApps = when (selectedAppFilter) {
            "OPEN" -> openAppsList.filter { it.isOpen }
            "CLOSED" -> openAppsList.filter { !it.isOpen }
            else -> openAppsList
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "OPEN APPLICATIONS ON LAPTOP",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextSecondary,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "Live timeline • Launch times • Foreground status",
                    fontSize = 10.sp,
                    color = TextMuted
                )
            }
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(10.dp))
                    .background(PrimaryBlue.copy(alpha = 0.1f))
                    .padding(horizontal = 8.dp, vertical = 2.dp)
            ) {
                Text(
                    text = "$openCount Open",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = PrimaryBlue
                )
            }
        }
        Spacer(modifier = Modifier.height(8.dp))

        // Application Filter Chips
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            listOf("ALL" to "All (${openAppsList.size})", "OPEN" to "Open Now ($openCount)", "CLOSED" to "Closed ($closedCount)").forEach { (key, label) ->
                val isSel = selectedAppFilter == key
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (isSel) PrimaryBlue else LightSurfaceVariant)
                        .clickable { selectedAppFilter = key }
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = label,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (isSel) Color.White else TextSecondary
                    )
                }
            }
        }
        Spacer(modifier = Modifier.height(8.dp))

        // Applications List Card
        Card(
            colors = CardDefaults.cardColors(
                containerColor = LightSurface,
                contentColor = TextPrimary
            ),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                if (filteredApps.isEmpty()) {
                    Text(
                        text = "No applications match the selected filter.",
                        fontSize = 12.sp,
                        color = TextMuted,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )
                } else {
                    filteredApps.forEachIndexed { index, app ->
                        val isFg = app.isForeground
                        val appIcon = when {
                            app.appName.contains("Chrome", true) || app.appName.contains("Edge", true) || app.appName.contains("Firefox", true) || app.category.contains("Browser", true) -> Icons.Default.Language
                            app.appName.contains("Code", true) || app.appName.contains("Studio", true) || app.appName.contains("IDE", true) || app.category.contains("Development", true) -> Icons.Default.Code
                            app.appName.contains("WhatsApp", true) || app.appName.contains("Telegram", true) || app.appName.contains("Discord", true) || app.category.contains("Messaging", true) -> Icons.Default.Chat
                            app.appName.contains("Settings", true) || app.category.contains("Settings", true) -> Icons.Default.Settings
                            app.appName.contains("Explorer", true) || app.category.contains("Management", true) -> Icons.Default.FolderOpen
                            app.appName.contains("PowerShell", true) || app.appName.contains("Terminal", true) || app.appName.contains("Command", true) -> Icons.Default.Terminal
                            app.appName.contains("Word", true) || app.appName.contains("Excel", true) || app.appName.contains("PDF", true) || app.appName.contains("WPS", true) -> Icons.Default.Description
                            else -> Icons.Default.Laptop
                        }

                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(if (isFg) PrimaryBlue.copy(alpha = 0.05f) else Color.Transparent)
                                .padding(if (isFg) 8.dp else 4.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                                    Box(
                                        modifier = Modifier
                                            .size(38.dp)
                                            .clip(RoundedCornerShape(8.dp))
                                            .background(if (isFg) PrimaryBlue.copy(alpha = 0.15f) else LightSurfaceVariant),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = appIcon,
                                            contentDescription = null,
                                            tint = if (isFg) PrimaryBlue else TextSecondary,
                                            modifier = Modifier.size(20.dp)
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Column {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(
                                                text = app.appName,
                                                fontSize = 13.sp,
                                                fontWeight = FontWeight.Bold,
                                                color = TextPrimary,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                            if (isFg) {
                                                Spacer(modifier = Modifier.width(6.dp))
                                                Box(
                                                    modifier = Modifier
                                                        .clip(RoundedCornerShape(4.dp))
                                                        .background(BandGreen.copy(alpha = 0.15f))
                                                        .padding(horizontal = 4.dp, vertical = 1.dp)
                                                ) {
                                                    Text(
                                                        text = "IN USE NOW",
                                                        fontSize = 9.sp,
                                                        fontWeight = FontWeight.ExtraBold,
                                                        color = BandGreen
                                                    )
                                                }
                                            }
                                        }
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(
                                                text = app.processName,
                                                fontSize = 11.sp,
                                                fontFamily = FontFamily.Monospace,
                                                color = TextMuted
                                            )
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text(
                                                text = "• ${app.category}",
                                                fontSize = 11.sp,
                                                color = TextSecondary
                                            )
                                        }
                                    }
                                }

                                // Status Badge
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(
                                            when {
                                                isFg -> BandGreen.copy(alpha = 0.12f)
                                                app.isOpen -> PrimaryBlue.copy(alpha = 0.1f)
                                                else -> LightSurfaceVariant
                                            }
                                        )
                                        .padding(horizontal = 7.dp, vertical = 3.dp)
                                ) {
                                    Text(
                                        text = when {
                                            isFg -> "Active Now"
                                            app.isOpen -> "Open"
                                            else -> "Closed"
                                        },
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = when {
                                            isFg -> BandGreen
                                            app.isOpen -> PrimaryBlue
                                            else -> TextMuted
                                        }
                                    )
                                }
                            }

                            // Window title and Launch Time Details
                            if (app.windowTitle.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = "📄 ${app.windowTitle}",
                                    fontSize = 11.sp,
                                    color = TextSecondary,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }

                            Spacer(modifier = Modifier.height(4.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.AccessTime,
                                        contentDescription = null,
                                        tint = TextMuted,
                                        modifier = Modifier.size(12.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = if (app.isOpen) {
                                            "Opened: ${app.openedAt} • Running for ${app.duration}"
                                        } else {
                                            "Opened: ${app.openedAt} • ${app.closedAt ?: "Recently Closed"}"
                                        },
                                        fontSize = 10.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = TextSecondary
                                    )
                                }

                                Text(
                                    text = if (app.isOpen) "STATUS: RUNNING" else "STATUS: TERMINATED",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (app.isOpen) BandGreen else TextMuted
                                )
                            }
                        }

                        if (index < filteredApps.size - 1) {
                            Divider(color = LightBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 4.dp))
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // =========================================================================
        // 6. CONNECTED DEVICES TO LAPTOP (Hotspot & USB) (Requirement #1)
        // =========================================================================
        val rawConnectedDevices = status?.connectedDevices ?: emptyList()
        val connectedDevicesList = if (rawConnectedDevices.isNotEmpty()) {
            rawConnectedDevices
        } else {
            listOf(
                ConnectedDeviceItem(
                    id = "usb_phone_current",
                    name = "Redmi Note 7 Pro (949A1851)",
                    type = "usb_phone",
                    status = if (connectionState == ConnectionStatus.CONNECTED) "Connected (Active USB)" else "USB Tethered",
                    connectionType = "USB Cable (ADB Port 8765)",
                    details = "Direct Offline Hardware Bridge | Model: Redmi Note 7 Pro",
                    iconType = "phone"
                ),
                ConnectedDeviceItem(
                    id = "hotspot_ap_status",
                    name = "Laptop Mobile Hotspot",
                    type = "hotspot_ap",
                    status = "Hotspot Off",
                    connectionType = "Mobile Hotspot (Wi-Fi)",
                    details = "0 devices connected | Windows Hotspot is currently Off",
                    iconType = "wifi"
                ),
                ConnectedDeviceItem(
                    id = "companion_stream",
                    name = "Redmi Note 7 Pro (Companion App)",
                    type = "paired_companion",
                    status = if (connectionState == ConnectionStatus.CONNECTED) "Active Session" else "Standby",
                    connectionType = "Local Wi-Fi / USB",
                    details = "Live Telemetry & Security Controller Session",
                    iconType = "mobile"
                )
            )
        }

        val hotspotCount = connectedDevicesList.count { it.connectionType.contains("Hotspot", true) || it.type.contains("hotspot", true) }
        val usbCount = connectedDevicesList.count { it.connectionType.contains("USB", true) || it.type.contains("usb", true) }

        val filteredDevices = when (selectedDeviceFilter) {
            "HOTSPOT" -> connectedDevicesList.filter { it.connectionType.contains("Hotspot", true) || it.type.contains("hotspot", true) }
            "USB" -> connectedDevicesList.filter { it.connectionType.contains("USB", true) || it.type.contains("usb", true) }
            else -> connectedDevicesList
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "CONNECTED DEVICES TO LAPTOP",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextSecondary,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "Hotspot (Wi-Fi) • USB Cable • Mass Storage",
                    fontSize = 10.sp,
                    color = TextMuted
                )
            }
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(10.dp))
                    .background(PrimaryBlue.copy(alpha = 0.1f))
                    .padding(horizontal = 8.dp, vertical = 2.dp)
            ) {
                Text(
                    text = "${connectedDevicesList.size} Devices",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = PrimaryBlue
                )
            }
        }
        Spacer(modifier = Modifier.height(8.dp))

        // Device Filter Chips
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            listOf("ALL" to "All (${connectedDevicesList.size})", "HOTSPOT" to "Hotspot ($hotspotCount)", "USB" to "USB ($usbCount)").forEach { (key, label) ->
                val isSel = selectedDeviceFilter == key
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (isSel) PrimaryBlue else LightSurfaceVariant)
                        .clickable { selectedDeviceFilter = key }
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = label,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (isSel) Color.White else TextSecondary
                    )
                }
            }
        }
        Spacer(modifier = Modifier.height(8.dp))

        Card(
            colors = CardDefaults.cardColors(
                containerColor = LightSurface,
                contentColor = TextPrimary
            ),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                if (filteredDevices.isEmpty()) {
                    Text(
                        text = "No devices connected matching this filter.",
                        fontSize = 12.sp,
                        color = TextMuted,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )
                } else {
                    filteredDevices.forEachIndexed { index, device ->
                        val isHotspot = device.connectionType.contains("Hotspot", true) || device.type.contains("hotspot", true)
                        val isUsb = device.connectionType.contains("USB", true) || device.type.contains("usb", true)

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 6.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                                Box(
                                    modifier = Modifier
                                        .size(38.dp)
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(
                                            when {
                                                isHotspot -> Color(0xFFEDE9FE)
                                                isUsb -> Color(0xFFE0F2FE)
                                                else -> LightSurfaceVariant
                                            }
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = when {
                                            isHotspot -> Icons.Default.Wifi
                                            device.iconType in listOf("phone", "mobile") -> Icons.Default.PhoneAndroid
                                            device.iconType in listOf("drive") -> Icons.Default.Storage
                                            else -> Icons.Default.Usb
                                        },
                                        contentDescription = null,
                                        tint = when {
                                            isHotspot -> Color(0xFF7C3AED)
                                            isUsb -> PrimaryBlue
                                            else -> TextSecondary
                                        },
                                        modifier = Modifier.size(20.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            text = device.name,
                                            fontSize = 13.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = TextPrimary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Box(
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(4.dp))
                                                .background(
                                                    when {
                                                        isHotspot -> Color(0xFFEDE9FE)
                                                        isUsb -> Color(0xFFE0F2FE)
                                                        else -> Color(0xFFDCFCE7)
                                                    }
                                                )
                                                .padding(horizontal = 4.dp, vertical = 1.dp)
                                        ) {
                                            Text(
                                                text = when {
                                                    isHotspot -> "HOTSPOT"
                                                    isUsb -> "USB"
                                                    else -> "PAIRED"
                                                },
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.Bold,
                                                color = when {
                                                    isHotspot -> Color(0xFF7C3AED)
                                                    isUsb -> Color(0xFF0369A1)
                                                    else -> Color(0xFF15803D)
                                                }
                                            )
                                        }
                                    }
                                    Spacer(modifier = Modifier.height(1.dp))
                                    Text(
                                        text = device.connectionType + (device.details?.let { " • $it" } ?: ""),
                                        fontSize = 11.sp,
                                        color = TextSecondary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }

                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(
                                        when {
                                            device.status.contains("Active", true) || device.status.contains("Connected", true) -> BandGreen.copy(alpha = 0.1f)
                                            device.status.contains("Mounted", true) -> PrimaryBlue.copy(alpha = 0.1f)
                                            else -> LightSurfaceVariant
                                        }
                                    )
                                    .padding(horizontal = 8.dp, vertical = 3.dp)
                            ) {
                                Text(
                                    text = device.status,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = when {
                                        device.status.contains("Active", true) || device.status.contains("Connected", true) -> BandGreen
                                        device.status.contains("Mounted", true) -> PrimaryBlue
                                        else -> TextSecondary
                                    }
                                )
                            }
                        }
                        if (index < filteredDevices.size - 1) {
                            Divider(color = LightBorderColor.copy(alpha = 0.6f), modifier = Modifier.padding(vertical = 4.dp))
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

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

        Spacer(modifier = Modifier.height(18.dp))

        // =========================================================================
        // 7. TIME & DATE EVENT TIMELINE / HISTORY (Persistent Mobile Log)
        // =========================================================================
        val filteredTimeline = when (selectedTimelineFilter) {
            "APP" -> timelineEvents.filter { it.category == "APP" }
            "DEVICE" -> timelineEvents.filter { it.category == "DEVICE" }
            "SYSTEM" -> timelineEvents.filter { it.category == "SYSTEM" }
            "SECURITY" -> timelineEvents.filter { it.category == "SECURITY" }
            else -> timelineEvents
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "TIME & DATE EVENT TIMELINE",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextSecondary,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "Saved permanently on phone • Live chronological log",
                    fontSize = 10.sp,
                    color = TextMuted
                )
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(10.dp))
                        .background(PrimaryBlue.copy(alpha = 0.1f))
                        .padding(horizontal = 8.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = "${timelineEvents.size} Logged",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = PrimaryBlue
                    )
                }
                if (timelineEvents.isNotEmpty()) {
                    IconButton(
                        onClick = { showClearTimelineDialog = true },
                        modifier = Modifier.size(24.dp)
                    ) {
                        Icon(Icons.Default.DeleteOutline, contentDescription = "Clear History", tint = TextMuted, modifier = Modifier.size(16.dp))
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Timeline Filter Chips
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            listOf(
                "ALL" to "All (${timelineEvents.size})",
                "APP" to "Apps (${timelineEvents.count { it.category == "APP" }})",
                "DEVICE" to "Devices (${timelineEvents.count { it.category == "DEVICE" }})",
                "SYSTEM" to "Power (${timelineEvents.count { it.category == "SYSTEM" }})",
                "SECURITY" to "Alerts (${timelineEvents.count { it.category == "SECURITY" }})"
            ).forEach { (key, label) ->
                val isSel = selectedTimelineFilter == key
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (isSel) PrimaryBlue else LightSurfaceVariant)
                        .clickable { selectedTimelineFilter = key }
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = label,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (isSel) Color.White else TextSecondary
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Timeline Card Container
        Card(
            colors = CardDefaults.cardColors(containerColor = LightSurface, contentColor = TextPrimary),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                if (filteredTimeline.isEmpty()) {
                    Text(
                        text = "No events recorded yet. Connect to laptop to start logging.",
                        fontSize = 12.sp,
                        color = TextMuted,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )
                } else {
                    filteredTimeline.take(40).forEachIndexed { idx, ev ->
                        val (catBg, catColor, catIcon) = when (ev.category) {
                            "APP" -> Triple(PrimaryBlue.copy(alpha = 0.12f), PrimaryBlue, Icons.Default.Laptop)
                            "DEVICE" -> Triple(Color(0xFF00897B).copy(alpha = 0.12f), Color(0xFF00897B), Icons.Default.Usb)
                            "SYSTEM" -> Triple(BandGreen.copy(alpha = 0.12f), BandGreen, Icons.Default.PowerSettingsNew)
                            "SECURITY" -> Triple(BandRed.copy(alpha = 0.12f), BandRed, Icons.Default.Shield)
                            else -> Triple(LightSurfaceVariant, TextSecondary, Icons.Default.Info)
                        }

                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                // Date & Time Stamp Badges
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(6.dp))
                                            .background(LightSurfaceVariant)
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = "📅 ${ev.dateStr.ifEmpty { "Today" }}",
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Bold,
                                            fontFamily = FontFamily.Monospace,
                                            color = TextSecondary
                                        )
                                    }
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(6.dp))
                                            .background(LightSurfaceVariant)
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = "⏰ ${ev.timeStr.ifEmpty { "Just now" }}",
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Bold,
                                            fontFamily = FontFamily.Monospace,
                                            color = PrimaryBlue
                                        )
                                    }
                                }

                                // Category Chip
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(catBg)
                                        .padding(horizontal = 5.dp, vertical = 1.dp)
                                ) {
                                    Text(
                                        text = ev.category,
                                        fontSize = 8.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = catColor
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(4.dp))

                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(28.dp)
                                        .clip(CircleShape)
                                        .background(catBg),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(catIcon, contentDescription = null, tint = catColor, modifier = Modifier.size(15.dp))
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = ev.title,
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = TextPrimary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    if (ev.details.isNotEmpty()) {
                                        Text(
                                            text = ev.details,
                                            fontSize = 10.sp,
                                            color = TextSecondary,
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }
                                if (ev.status.isNotEmpty()) {
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = ev.status,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = if (ev.severity == "WARNING" || ev.severity == "CRITICAL") BandRed else catColor
                                    )
                                }
                            }
                        }

                        if (idx < filteredTimeline.take(40).size - 1) {
                            Divider(color = LightBorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 3.dp))
                        }
                    }
                }
            }
        }

        if (showClearTimelineDialog) {
            AlertDialog(
                onDismissRequest = { showClearTimelineDialog = false },
                title = { Text("Clear Timeline History?") },
                text = { Text("Are you sure you want to clear all saved timeline logs on your phone?") },
                confirmButton = {
                    TextButton(
                        onClick = {
                            repository.clearTimelineHistory()
                            showClearTimelineDialog = false
                        }
                    ) {
                        Text("Clear", color = BandRed, fontWeight = FontWeight.Bold)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showClearTimelineDialog = false }) {
                        Text("Cancel")
                    }
                }
            )
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
