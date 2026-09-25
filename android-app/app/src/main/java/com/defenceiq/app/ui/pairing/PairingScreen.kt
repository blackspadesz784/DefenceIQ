package com.defenceiq.app.ui.pairing

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.defenceiq.app.network.CloudRelayClient
import com.defenceiq.app.network.DefenceIqRepository
import com.defenceiq.app.ui.theme.*
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

    var activeToken by remember { mutableStateOf(CloudRelayClient.generateToken()) }
    var inputToken by remember { mutableStateOf("11C6C497") }
    var isListening by remember { mutableStateOf(false) }

    // Direct LAN fallback fields
    var showAdvancedLan by remember { mutableStateOf(false) }
    var host by remember { mutableStateOf(repository.host) }
    var port by remember { mutableStateOf(repository.port.toString()) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val pairedDevice by repository.pairedDevice.collectAsState()

    // When handshake received, auto-navigate
    LaunchedEffect(pairedDevice) {
        if (pairedDevice != null) {
            Toast.makeText(context, "Paired with ${pairedDevice?.hostname}!", Toast.LENGTH_SHORT).show()
            onPairedSuccess()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DarkBackground)
            .verticalScroll(scrollState)
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        Icon(
            imageVector = Icons.Default.Security,
            contentDescription = "DefenceIQ Shield",
            tint = NeonGreen,
            modifier = Modifier.size(64.dp)
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "DefenceIQ",
            fontSize = 30.sp,
            fontWeight = FontWeight.Bold,
            color = TextPrimary,
            letterSpacing = 1.sp
        )

        Text(
            text = "Token-Based Device Pairing (No IP Required)",
            fontSize = 13.sp,
            color = CyberBlue,
            fontWeight = FontWeight.Medium
        )

        Spacer(modifier = Modifier.height(20.dp))

        // Generated Token Card
        Card(
            colors = CardDefaults.cardColors(containerColor = DarkSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, NeonGreen, RoundedCornerShape(16.dp))
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "YOUR MOBILE PAIRING TOKEN",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = CyberBlue,
                    letterSpacing = 1.sp
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = activeToken,
                    fontSize = 26.sp,
                    fontWeight = FontWeight.ExtraBold,
                    fontFamily = FontFamily.Monospace,
                    color = TextPrimary,
                    letterSpacing = 2.sp
                )

                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            clipboardManager.setText(AnnotatedString(activeToken))
                            Toast.makeText(context, "Token copied to clipboard!", Toast.LENGTH_SHORT).show()
                        },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberBlue)
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = "Copy", modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Copy", fontSize = 12.sp)
                    }

                    OutlinedButton(
                        onClick = {
                            activeToken = CloudRelayClient.generateToken()
                            if (isListening) {
                                repository.pairWithToken(activeToken)
                            }
                        },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = "Regenerate", modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("New", fontSize = 12.sp)
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Button(
                    onClick = {
                        isListening = true
                        errorMessage = null
                        repository.pairWithToken(activeToken)
                        Toast.makeText(context, "Listening for laptop on secure cloud relay...", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isListening) DarkSurfaceVariant else NeonGreen,
                        contentColor = if (isListening) NeonGreen else DarkBackground
                    )
                ) {
                    Text(
                        text = if (isListening) "Waiting for Laptop to Link..." else "Start Listening for Laptop",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = "Enter this token on your laptop (start_agent.bat or Web Dashboard). Once entered, devices will securely link across any network without IP addresses.",
                    fontSize = 11.sp,
                    color = TextSecondary,
                    textAlign = TextAlign.Center,
                    lineHeight = 16.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Or enter laptop token
        Card(
            colors = CardDefaults.cardColors(containerColor = DarkSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, BorderColor, RoundedCornerShape(14.dp))
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "OR PAIR USING LAPTOP TOKEN",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextSecondary,
                    letterSpacing = 1.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = inputToken,
                    onValueChange = { inputToken = it.uppercase() },
                    placeholder = { Text("e.g. 11C6C497 or DIQ-XXXX-XXXX") },
                    leadingIcon = { Icon(Icons.Default.Lock, contentDescription = null, tint = NeonGreen) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = NeonGreen,
                        unfocusedBorderColor = BorderColor
                    )
                )

                Spacer(modifier = Modifier.height(10.dp))

                Button(
                    onClick = {
                        val trimmed = inputToken.trim().uppercase()
                        if (trimmed.length >= 4) {
                            isListening = true
                            repository.pairWithToken(trimmed)
                        } else {
                            errorMessage = "Token must be at least 4 characters."
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = CyberBlue, contentColor = DarkBackground)
                ) {
                    Text("Link with Entered Token", fontWeight = FontWeight.Bold)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Privacy Guarantee Card
        Card(
            colors = CardDefaults.cardColors(containerColor = DarkSurfaceVariant),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = "🛡️ PRIVACY & LEAST PRIVILEGE GUARANTEE",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = NeonGreen,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "DefenceIQ only accesses user-authorized folders. Threat telemetry is metadata-only (process names, SHA-256 hashes, entropy scores). Sensitive document and file contents are NEVER read or transmitted.",
                    fontSize = 11.sp,
                    color = TextSecondary,
                    lineHeight = 15.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Advanced Direct Wi-Fi Toggle
        Text(
            text = if (showAdvancedLan) "▼ Hide Direct LAN Options" else "▶ Advanced: Direct Local Wi-Fi Connection",
            fontSize = 12.sp,
            color = CyberBlue,
            modifier = Modifier
                .clickable { showAdvancedLan = !showAdvancedLan }
                .padding(vertical = 4.dp)
        )

        if (showAdvancedLan) {
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = host,
                onValueChange = { host = it },
                label = { Text("Laptop LAN IP (e.g. 192.168.1.4)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    focusedBorderColor = NeonGreen,
                    unfocusedBorderColor = BorderColor
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
                    focusedBorderColor = NeonGreen,
                    unfocusedBorderColor = BorderColor
                )
            )
            Spacer(modifier = Modifier.height(8.dp))
            Button(
                onClick = {
                    val p = port.toIntOrNull() ?: 8765
                    val tok = if (inputToken.isNotEmpty()) inputToken else activeToken
                    coroutineScope.launch {
                        val res = repository.pairAndConnect(host, p, tok)
                        if (res.isSuccess) {
                            onPairedSuccess()
                        } else {
                            errorMessage = res.exceptionOrNull()?.message
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = DarkSurfaceVariant, contentColor = TextPrimary)
            ) {
                Text("Direct Wi-Fi Connect")
            }
        }

        if (errorMessage != null) {
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = errorMessage!!,
                color = BandRed,
                fontSize = 12.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}
