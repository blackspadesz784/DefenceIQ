package com.defenceiq.app.ui.alerts

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.defenceiq.app.data.Incident
import com.defenceiq.app.data.SecurityAlert
import com.defenceiq.app.network.DefenceIqRepository
import com.defenceiq.app.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun AlertsScreen(
    repository: DefenceIqRepository
) {
    val incidents by repository.incidents.collectAsState()
    val securityAlerts by repository.securityAlerts.collectAsState()
    val coroutineScope = rememberCoroutineScope()
    var selectedTab by remember { mutableStateOf(0) } // 0 = Security Alerts, 1 = Threat Incidents
    var rollingBackId by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(LightBackground)
            .padding(16.dp)
    ) {
        // Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Security & Threat Alerts",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary
                )
                Text(
                    text = "Live audit feed and endpoint incident alerts",
                    fontSize = 12.sp,
                    color = TextSecondary
                )
            }

            IconButton(
                onClick = {
                    coroutineScope.launch {
                        repository.refreshIncidents()
                        repository.refreshSecurityAlerts()
                    }
                }
            ) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = PrimaryBlue)
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Tab Selector: Security Events vs Threat Incidents
        TabRow(
            selectedTabIndex = selectedTab,
            containerColor = LightSurface,
            contentColor = PrimaryBlue,
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .border(1.dp, LightBorderColor, RoundedCornerShape(10.dp))
        ) {
            Tab(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                text = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Security Alerts (${securityAlerts.size})",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 12.sp
                        )
                    }
                }
            )
            Tab(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1 },
                text = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Warning, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Threat Incidents (${incidents.size})",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 12.sp
                        )
                    }
                }
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        // =========================================================================
        // TAB 0: AUTOMATIC SECURITY ALERTS (Requirement #2)
        // =========================================================================
        if (selectedTab == 0) {
            if (securityAlerts.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = BandGreen,
                            modifier = Modifier.size(48.dp)
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "No Security Alerts",
                            color = TextPrimary,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Connections, disconnections, and access events are normal.",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                    }
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(securityAlerts, key = { it.id }) { alert ->
                        SecurityAlertCard(alert = alert)
                    }
                }
            }
        }

        // =========================================================================
        // TAB 1: THREAT INCIDENTS & ROLLBACK
        // =========================================================================
        if (selectedTab == 1) {
            if (incidents.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = BandGreen,
                            modifier = Modifier.size(48.dp)
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "No Threat Incidents",
                            color = TextPrimary,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "All endpoint systems running within baseline parameters.",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                    }
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(incidents, key = { it.incidentId }) { incident ->
                        IncidentCard(
                            incident = incident,
                            isRollingBack = rollingBackId == incident.incidentId,
                            onRollback = {
                                rollingBackId = incident.incidentId
                                coroutineScope.launch {
                                    repository.rollbackIncident(incident.incidentId)
                                    rollingBackId = null
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun SecurityAlertCard(alert: SecurityAlert) {
    val (severityColor, severityBg) = when (alert.severity) {
        "CRITICAL" -> Pair(BandRed, BandRed.copy(alpha = 0.1f))
        "WARNING" -> Pair(BandOrange, BandOrange.copy(alpha = 0.1f))
        else -> Pair(PrimaryBlue, PrimaryBlue.copy(alpha = 0.08f))
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = LightSurface),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, LightBorderColor, RoundedCornerShape(12.dp))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
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
                            .background(severityColor)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = alert.eventType.replace('_', ' '),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(severityBg)
                        .padding(horizontal = 8.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = alert.severity,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = severityColor
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = alert.details,
                fontSize = 12.sp,
                color = TextSecondary,
                lineHeight = 16.sp
            )

            Spacer(modifier = Modifier.height(8.dp))
            Divider(color = LightBorderColor.copy(alpha = 0.6f))
            Spacer(modifier = Modifier.height(6.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "Device: ${alert.deviceName} (${alert.deviceType})",
                    fontSize = 11.sp,
                    color = TextMuted
                )
                Text(
                    text = alert.timestamp,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = TextMuted
                )
            }
        }
    }
}

@Composable
fun IncidentCard(
    incident: Incident,
    isRollingBack: Boolean,
    onRollback: () -> Unit
) {
    val bandColor = when (incident.riskBand) {
        "RED" -> BandRed
        "ORANGE" -> BandOrange
        "YELLOW" -> BandYellow
        else -> BandGreen
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = LightSurface),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, bandColor.copy(alpha = 0.4f), RoundedCornerShape(12.dp))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header: Band, Score, and Status
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(bandColor)
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = "${incident.riskBand} • ${incident.riskScore}/100",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }

                val statusColor = when (incident.status) {
                    "CONTAINED" -> StatusContained
                    "ROLLED_BACK" -> StatusRolledBack
                    "RESOLVED" -> BandGreen
                    else -> BandRed
                }
                Text(
                    text = incident.status,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = statusColor
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Root process info
            Text(
                text = "${incident.rootProcessName} (PID: ${incident.rootPid})",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Explainability Signals
            if (incident.contributingSignals.isNotEmpty()) {
                Text(
                    text = "CONTRIBUTING SIGNALS:",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = PrimaryBlue,
                    letterSpacing = 0.5.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                incident.contributingSignals.forEach { signal ->
                    Row(
                        modifier = Modifier.padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "+${signal.weight}",
                            color = bandColor,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                            modifier = Modifier.width(32.dp)
                        )
                        Text(
                            text = "${signal.name}: ${signal.description}",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            // Explanation Narrative
            if (incident.explanation.isNotBlank()) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = LightSurfaceVariant),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = incident.explanation,
                        fontSize = 12.sp,
                        color = TextPrimary,
                        modifier = Modifier.padding(10.dp),
                        lineHeight = 16.sp
                    )
                }
                Spacer(modifier = Modifier.height(10.dp))
            }

            // Rollback button if contained or open with actions
            if (incident.status == "CONTAINED" || incident.riskBand in listOf("ORANGE", "RED")) {
                Button(
                    onClick = onRollback,
                    enabled = !isRollingBack && incident.status != "ROLLED_BACK",
                    colors = ButtonDefaults.buttonColors(
                        containerColor = PrimaryBlue,
                        contentColor = Color.White
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (isRollingBack) {
                        CircularProgressIndicator(
                            color = Color.White,
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(Icons.Default.Undo, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = if (incident.status == "ROLLED_BACK") "CONTAINMENT ROLLED BACK" else "UNDO CONTAINMENT (ROLLBACK)",
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }
            }
        }
    }
}
