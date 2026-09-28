package com.defenceiq.app.ui.pairing

import android.widget.Toast
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.defenceiq.app.network.ConnectionStatus
import com.defenceiq.app.network.DefenceIqRepository
import com.defenceiq.app.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun PairingScreen(
    repository: DefenceIqRepository,
    onPairedSuccess: () -> Unit
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val coroutineScope = rememberCoroutineScope()
    val scrollState = rememberScrollState()

    val connectionState by repository.connectionState.collectAsState()
    val pairedDevice by repository.pairedDevice.collectAsState()
    val lastError by repository.lastError.collectAsState()

    // 0 = Laptop -> Phone (Enter Laptop Token), 1 = Phone -> Laptop (Generate Mobile Token)
    var selectedFlowTab by remember { mutableStateOf(0) }

    // Laptop -> Phone flow
    var inputToken by remember { mutableStateOf("") }
    var isVerifying by remember { mutableStateOf(false) }
    var showConfirmDialog by remember { mutableStateOf(false) }
    var userFriendlyError by remember { mutableStateOf<String?>(null) }

    // Phone -> Laptop reverse flow
    var mobileToken by remember { mutableStateOf(repository.generateMobileToken()) }
    var secondsLeft by remember { mutableStateOf(600) }

    // Advanced Direct LAN
    var showAdvancedLan by remember { mutableStateOf(false) }
    var host by remember { mutableStateOf(repository.host) }
    var port by remember { mutableStateOf(repository.port.toString()) }

    // 10-minute countdown timer for generated token
    LaunchedEffect(mobileToken) {
        secondsLeft = 600
        while (secondsLeft > 0) {
            delay(1000)
            secondsLeft--
        }
    }

    // Auto-navigate when connected
    LaunchedEffect(connectionState, pairedDevice) {
        if (connectionState == ConnectionStatus.CONNECTED && pairedDevice != null) {
            Toast.makeText(context, "Securely paired with ${pairedDevice?.hostname}!", Toast.LENGTH_SHORT).show()
            onPairedSuccess()
        }
    }

    // Reflect repository error
    LaunchedEffect(lastError) {
        if (lastError != null) {
            userFriendlyError = lastError
            isVerifying = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(LightBackground)
            .verticalScroll(scrollState)
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(12.dp))

        // Shield / Security Header Icon
        Box(
            modifier = Modifier
                .size(60.dp)
                .clip(CircleShape)
                .background(LightSurfaceVariant),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = "DefenceIQ Security",
                tint = PrimaryBlue,
                modifier = Modifier.size(32.dp)
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "Device Pairing",
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold,
            color = TextPrimary
        )

        Text(
            text = "Cryptographically secure, token-based pairing",
            fontSize = 13.sp,
            color = TextSecondary
        )

        Spacer(modifier = Modifier.height(20.dp))

        // Already Paired Banner
        if (connectionState == ConnectionStatus.CONNECTED && pairedDevice != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = LightSurface),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, BandGreen, RoundedCornerShape(14.dp))
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = BandGreen, modifier = Modifier.size(36.dp))
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Device Currently Paired",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Text(
                        text = "Connected to ${pairedDevice?.hostname} (${pairedDevice?.deviceId})",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(
                            onClick = onPairedSuccess,
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryBlue)
                        ) {
                            Text("Open Dashboard")
                        }
                        OutlinedButton(
                            onClick = { repository.revokePairing() },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = BandRed)
                        ) {
                            Text("Unpair")
                        }
                    }
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        // Segmented Control for Pairing Direction
        TabRow(
            selectedTabIndex = selectedFlowTab,
            containerColor = LightSurface,
            contentColor = PrimaryBlue,
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .border(1.dp, LightBorderColor, RoundedCornerShape(12.dp))
        ) {
            Tab(
                selected = selectedFlowTab == 0,
                onClick = { selectedFlowTab = 0; userFriendlyError = null },
                text = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Laptop, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Laptop → Phone", fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                    }
                }
            )
            Tab(
                selected = selectedFlowTab == 1,
                onClick = { selectedFlowTab = 1; userFriendlyError = null },
                text = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Smartphone, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Phone → Laptop", fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                    }
                }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // =========================================================================
        // FLOW 1: LAPTOP → PHONE (Enter Laptop Token)
        // =========================================================================
        if (selectedFlowTab == 0) {
            Card(
                colors = CardDefaults.cardColors(containerColor = LightSurface),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Key, contentDescription = null, tint = PrimaryBlue, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "ENTER LAPTOP PAIRING TOKEN",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = PrimaryBlue,
                            letterSpacing = 0.5.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = "Open the DefenceIQ application on your laptop. Copy or read the pairing token displayed on the laptop dashboard and enter it below.",
                        fontSize = 12.sp,
                        color = TextSecondary,
                        lineHeight = 17.sp
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    OutlinedTextField(
                        value = inputToken,
                        onValueChange = {
                            inputToken = it.uppercase().trim()
                            userFriendlyError = null
                        },
                        placeholder = { Text("e.g. 11C6C497 or DIQ-XXXX-XXXX") },
                        leadingIcon = { Icon(Icons.Default.VpnKey, contentDescription = null, tint = PrimaryBlue) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            focusedBorderColor = PrimaryBlue,
                            unfocusedBorderColor = LightBorderColor
                        )
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = {
                            val trimmed = inputToken.trim().uppercase()
                            if (trimmed.length < 4) {
                                userFriendlyError = "Please enter a valid pairing token (at least 4 characters)."
                            } else {
                                showConfirmDialog = true
                            }
                        },
                        enabled = !isVerifying && inputToken.isNotBlank(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(46.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = PrimaryBlue,
                            contentColor = Color.White
                        ),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        if (isVerifying) {
                            CircularProgressIndicator(color = Color.White, modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Verifying Token...")
                        } else {
                            Icon(Icons.Default.Link, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Verify & Pair Laptop", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        // =========================================================================
        // FLOW 2: PHONE → LAPTOP (Generate Mobile Token)
        // =========================================================================
        if (selectedFlowTab == 1) {
            Card(
                colors = CardDefaults.cardColors(containerColor = LightSurface),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, LightBorderColor, RoundedCornerShape(14.dp))
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "MOBILE PAIRING TOKEN",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = PrimaryBlue,
                        letterSpacing = 0.5.sp
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    // Prominent Token Display
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(10.dp))
                            .background(LightSurfaceVariant)
                            .border(1.dp, LightBorderColor, RoundedCornerShape(10.dp))
                            .padding(horizontal = 20.dp, vertical = 12.dp)
                    ) {
                        Text(
                            text = mobileToken,
                            fontSize = 24.sp,
                            fontWeight = FontWeight.ExtraBold,
                            fontFamily = FontFamily.Monospace,
                            color = TextPrimary,
                            letterSpacing = 2.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Countdown Timer
                    val minutes = secondsLeft / 60
                    val seconds = secondsLeft % 60
                    val timeFormatted = String.format("%02d:%02d", minutes, seconds)
                    Text(
                        text = if (secondsLeft > 0) "Token expires in $timeFormatted (single-use)" else "Token expired. Generate a new token.",
                        fontSize = 11.sp,
                        color = if (secondsLeft > 60) TextSecondary else BandRed,
                        fontFamily = FontFamily.Monospace
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = {
                                clipboardManager.setText(AnnotatedString(mobileToken))
                                Toast.makeText(context, "Token copied to clipboard!", Toast.LENGTH_SHORT).show()
                            }
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = "Copy", modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Copy Token", fontSize = 12.sp)
                        }

                        OutlinedButton(
                            onClick = {
                                mobileToken = repository.generateMobileToken()
                                userFriendlyError = null
                                Toast.makeText(context, "Fresh pairing token generated", Toast.LENGTH_SHORT).show()
                            }
                        ) {
                            Icon(Icons.Default.Refresh, contentDescription = "Regenerate", modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("New Token", fontSize = 12.sp)
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = "Enter this token on your laptop agent (in Web Dashboard or start_agent.bat). After verification, both devices will be securely paired.",
                        fontSize = 11.sp,
                        color = TextSecondary,
                        textAlign = TextAlign.Center,
                        lineHeight = 16.sp
                    )
                }
            }
        }

        // =========================================================================
        // USER CONFIRMATION DIALOG (Requirement #4)
        // =========================================================================
        if (showConfirmDialog) {
            AlertDialog(
                onDismissRequest = { showConfirmDialog = false },
                icon = { Icon(Icons.Default.Security, contentDescription = null, tint = PrimaryBlue) },
                title = { Text("Confirm Device Pairing", fontWeight = FontWeight.Bold) },
                text = {
                    Text(
                        "Are you sure you want to pair this mobile app with the laptop using token '$inputToken'?\n\n" +
                                "This will grant access to real-time endpoint security status and telemetry. The pairing token will be consumed immediately upon verification."
                    )
                },
                confirmButton = {
                    Button(
                        onClick = {
                            showConfirmDialog = false
                            isVerifying = true
                            userFriendlyError = null
                            coroutineScope.launch {
                                repository.pairWithToken(inputToken)
                                val res = repository.pairAndConnect(host, port.toIntOrNull() ?: 8765, inputToken)
                                isVerifying = false
                                if (res.isSuccess) {
                                    inputToken = ""
                                    onPairedSuccess()
                                } else {
                                    userFriendlyError = res.exceptionOrNull()?.message ?: "Pairing verification failed."
                                }
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryBlue)
                    ) {
                        Text("Confirm & Pair")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showConfirmDialog = false }) {
                        Text("Cancel")
                    }
                }
            )
        }

        // Friendly Error Message Banner (Requirement #9)
        if (userFriendlyError != null) {
            Spacer(modifier = Modifier.height(14.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = BandRed.copy(alpha = 0.08f)),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, BandRed.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.ErrorOutline, contentDescription = null, tint = BandRed, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = userFriendlyError!!,
                        color = BandRed,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        lineHeight = 16.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Privacy Guarantee Card
        Card(
            colors = CardDefaults.cardColors(containerColor = LightSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, LightBorderColor, RoundedCornerShape(12.dp))
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = BandGreen, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "PRIVACY & LEAST PRIVILEGE GUARANTEE",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = BandGreen,
                        letterSpacing = 0.5.sp
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "DefenceIQ only accesses user-authorized folders. Threat telemetry is metadata-only (process names, hashes, entropy). Sensitive file contents are NEVER transmitted.",
                    fontSize = 11.sp,
                    color = TextSecondary,
                    lineHeight = 15.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Advanced Direct LAN Fallback
        Text(
            text = if (showAdvancedLan) "▼ Hide Direct LAN Options" else "▶ Advanced: Direct Local Wi-Fi Connection",
            fontSize = 12.sp,
            color = PrimaryBlue,
            fontWeight = FontWeight.Medium,
            modifier = Modifier
                .clickable { showAdvancedLan = !showAdvancedLan }
                .padding(vertical = 4.dp)
        )

        if (showAdvancedLan) {
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = host,
                onValueChange = { host = it },
                label = { Text("Laptop LAN IP or Hostname") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    focusedBorderColor = PrimaryBlue,
                    unfocusedBorderColor = LightBorderColor
                )
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = port,
                onValueChange = { port = it },
                label = { Text("Port (default 8765)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    focusedBorderColor = PrimaryBlue,
                    unfocusedBorderColor = LightBorderColor
                )
            )
            Spacer(modifier = Modifier.height(8.dp))
            Button(
                onClick = {
                    val p = port.toIntOrNull() ?: 8765
                    val tok = if (inputToken.isNotEmpty()) inputToken else mobileToken
                    coroutineScope.launch {
                        val res = repository.pairAndConnect(host, p, tok)
                        if (res.isSuccess) {
                            onPairedSuccess()
                        } else {
                            userFriendlyError = repository.mapErrorMessage(res.exceptionOrNull())
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = LightSurfaceVariant, contentColor = TextPrimary)
            ) {
                Text("Direct Wi-Fi Connect")
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}
