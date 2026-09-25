package com.defenceiq.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.defenceiq.app.data.TransportsResponse
import com.defenceiq.app.network.DefenceIqRepository
import kotlinx.coroutines.launch

@Composable
fun TransportsScreen(
    repository: DefenceIqRepository,
    modifier: Modifier = Modifier
) {
    val transportsState by repository.transports.collectAsState()
    val scope = rememberCoroutineScope()
    var isRefreshing by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        repository.refreshTransports()
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFF0F172A))
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "COMMUNICATION TRANSPORTS",
                            color = Color(0xFF38BDF8),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.sp
                        )
                        Text(
                            text = "Connection Diagnostics",
                            color = Color.White,
                            fontSize = 22.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    IconButton(
                        onClick = {
                            scope.launch {
                                isRefreshing = true
                                repository.refreshTransports()
                                isRefreshing = false
                            }
                        }
                    ) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Refresh Transports",
                            tint = Color(0xFF38BDF8)
                        )
                    }
                }
            }

            val tr = transportsState
            if (tr == null) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            CircularProgressIndicator(color = Color(0xFF38BDF8))
                        }
                    }
                }
            } else {
                // 1. LAN Wi-Fi Transport Card
                item {
                    TransportCard(
                        title = "Local Network (Wi-Fi / LAN)",
                        icon = Icons.Default.Wifi,
                        isActive = true,
                        accentColor = Color(0xFF10B981),
                        details = listOf(
                            "Laptop IP" to tr.lan.ip,
                            "Port" to tr.lan.port.toString(),
                            "Connected Clients" to "${tr.lan.connectedClients} active session(s)",
                            "Protocols" to "HTTP REST + Bidirectional WebSockets"
                        )
                    )
                }

                // 2. USB Cable (ADB Port Forwarding) Card
                item {
                    val usbActive = tr.usb.devices.isNotEmpty() || tr.usb.activeForwards.isNotEmpty()
                    val dev = tr.usb.devices.firstOrNull()
                    TransportCard(
                        title = "USB Cable (ADB Port Forwarding)",
                        icon = Icons.Default.Usb,
                        isActive = usbActive,
                        accentColor = if (usbActive) Color(0xFF38BDF8) else Color(0xFF94A3B8),
                        details = listOf(
                            "ADB Daemon" to if (tr.usb.adbAvailable) "Available" else "Not Detected",
                            "Connected Device" to (dev?.let { "${it.model} (${it.serial})" } ?: "No USB cable connected"),
                            "Port Forwarding" to (tr.usb.activeForwards.firstOrNull() ?: "tcp:${tr.usb.remotePort} -> tcp:${tr.usb.localPort}"),
                            "Mode" to "Offline Direct Cable Link (No Wi-Fi needed)"
                        )
                    )
                }

                // 3. Bluetooth Low Energy (BLE) Card
                item {
                    val btActive = tr.bluetooth.bleSupported
                    TransportCard(
                        title = "Bluetooth Low Energy (BLE)",
                        icon = Icons.Default.Bluetooth,
                        isActive = btActive,
                        accentColor = if (btActive) Color(0xFF818CF8) else Color(0xFF64748B),
                        details = listOf(
                            "BLE Hardware / Driver" to if (tr.bluetooth.bleSupported) "Ready (Bleak WinRT)" else "Unavailable",
                            "Advertised Device" to tr.bluetooth.deviceName,
                            "GATT Service UUID" to tr.bluetooth.serviceUuid.take(18) + "...",
                            "MTU Framing" to "Chunked Binary Frames (Status, Alerts, Rollback)"
                        )
                    )
                }

                // 4. Cloud Relay (ntfy.sh Push Notifications) Card
                item {
                    val cloudActive = tr.cloud.enabled
                    TransportCard(
                        title = "Cloud Relay (Remote Push Alerts)",
                        icon = Icons.Default.Cloud,
                        isActive = cloudActive,
                        accentColor = if (cloudActive) Color(0xFFF59E0B) else Color(0xFF64748B),
                        details = listOf(
                            "Provider" to "Free & Open Source (ntfy.sh)",
                            "Push Channel" to tr.cloud.topic,
                            "Remote Alerts Delivered" to "${tr.cloud.totalAlertsSent} sent",
                            "Coverage" to "Away-from-home notifications for Orange/Red threats"
                        )
                    )
                }
            }
        }
    }
}

@Composable
fun TransportCard(
    title: String,
    icon: ImageVector,
    isActive: Boolean,
    accentColor: Color,
    details: List<Pair<String, String>>,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .background(accentColor.copy(alpha = 0.15f), RoundedCornerShape(8.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = icon,
                            contentDescription = title,
                            tint = accentColor,
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    Text(
                        text = title,
                        color = Color.White,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                Surface(
                    color = if (isActive) accentColor.copy(alpha = 0.2f) else Color(0xFF334155),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Text(
                        text = if (isActive) "ACTIVE" else "STANDBY",
                        color = if (isActive) accentColor else Color(0xFF94A3B8),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            Divider(color = Color(0xFF334155), thickness = 1.dp)
            Spacer(modifier = Modifier.height(10.dp))

            details.forEach { (label, value) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 3.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = label,
                        color = Color(0xFF94A3B8),
                        fontSize = 12.sp
                    )
                    Text(
                        text = value,
                        color = Color(0xFFE2E8F0),
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }
    }
}
