package com.defenceiq.app.ui.alerts

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Undo
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.defenceiq.app.data.Incident
import com.defenceiq.app.network.DefenceIqRepository
import com.defenceiq.app.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun AlertsScreen(
    repository: DefenceIqRepository
) {
    val incidents by repository.incidents.collectAsState()
    val coroutineScope = rememberCoroutineScope()
    var rollingBackId by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DarkBackground)
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "THREAT ALERTS & INCIDENTS",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary,
                letterSpacing = 1.sp
            )

            IconButton(
                onClick = {
                    coroutineScope.launch { repository.refreshIncidents() }
                }
            ) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberBlue)
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

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
                        tint = NeonGreen,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "No Threat Incidents",
                        color = TextPrimary,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "All endpoint systems running within baseline parameters.",
                        color = TextSecondary,
                        fontSize = 13.sp
                    )
                }
            }
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(14.dp)
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
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, bandColor.copy(alpha = 0.6f), RoundedCornerShape(12.dp))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header: Band, Score, and Status
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(bandColor)
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = "${incident.riskBand} • ${incident.riskScore}/100",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = DarkBackground
                        )
                    }
                }

                val statusColor = when (incident.status) {
                    "CONTAINED" -> StatusContained
                    "ROLLED_BACK" -> StatusRolledBack
                    "RESOLVED" -> NeonGreen
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
                    color = CyberBlue,
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
                    colors = CardDefaults.cardColors(containerColor = DarkSurfaceVariant),
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
                        containerColor = CyberBlue,
                        contentColor = DarkBackground
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (isRollingBack) {
                        CircularProgressIndicator(
                            color = DarkBackground,
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
