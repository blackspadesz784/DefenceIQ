package com.defenceiq.app.ui.pairing

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.defenceiq.app.network.DefenceIqRepository
import com.defenceiq.app.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun PairingScreen(
    repository: DefenceIqRepository,
    onPairedSuccess: () -> Unit
) {
    var host by remember { mutableStateOf(repository.host) }
    var port by remember { mutableStateOf(repository.port.toString()) }
    var token by remember { mutableStateOf(repository.token) }
    var isConnecting by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    val coroutineScope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DarkBackground)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Security,
            contentDescription = "DefenceIQ Shield",
            tint = NeonGreen,
            modifier = Modifier.size(72.dp)
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "DefenceIQ",
            fontSize = 32.sp,
            fontWeight = FontWeight.Bold,
            color = TextPrimary,
            letterSpacing = 1.sp
        )

        Text(
            text = "Pair with Laptop Security Agent",
            fontSize = 14.sp,
            color = TextSecondary
        )

        Spacer(modifier = Modifier.height(28.dp))

        // Info Card
        Card(
            colors = CardDefaults.cardColors(containerColor = DarkSurface),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, BorderColor, RoundedCornerShape(12.dp))
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "PAIRING INSTRUCTIONS",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = CyberBlue,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Launch DefenceIQ agent on your laptop. Enter the Local IP Address and the 8-character Pairing Token shown on the console banner.",
                    fontSize = 13.sp,
                    color = TextSecondary,
                    lineHeight = 18.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Host IP input
        OutlinedTextField(
            value = host,
            onValueChange = { host = it },
            label = { Text("Laptop LAN IP Address") },
            leadingIcon = { Icon(Icons.Default.Router, contentDescription = null, tint = NeonGreen) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = TextPrimary,
                unfocusedTextColor = TextPrimary,
                focusedBorderColor = NeonGreen,
                unfocusedBorderColor = BorderColor
            )
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Port input
        OutlinedTextField(
            value = port,
            onValueChange = { port = it },
            label = { Text("Port (default: 8765)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = TextPrimary,
                unfocusedTextColor = TextPrimary,
                focusedBorderColor = NeonGreen,
                unfocusedBorderColor = BorderColor
            )
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Pairing Token input
        OutlinedTextField(
            value = token,
            onValueChange = { token = it.uppercase() },
            label = { Text("8-Character Pairing Token") },
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

        if (errorMessage != null) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = errorMessage!!,
                color = BandRed,
                fontSize = 13.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
        }

        Spacer(modifier = Modifier.height(28.dp))

        // Pair button
        Button(
            onClick = {
                val parsedPort = port.toIntOrNull() ?: 8765
                isConnecting = true
                errorMessage = null
                coroutineScope.launch {
                    val result = repository.pairAndConnect(host, parsedPort, token)
                    isConnecting = false
                    if (result.isSuccess) {
                        onPairedSuccess()
                    } else {
                        errorMessage = result.exceptionOrNull()?.message ?: "Pairing failed. Check IP & Token."
                    }
                }
            },
            enabled = !isConnecting && host.isNotBlank() && token.isNotBlank(),
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = NeonGreen,
                contentColor = DarkBackground
            ),
            shape = RoundedCornerShape(10.dp)
        ) {
            if (isConnecting) {
                CircularProgressIndicator(
                    color = DarkBackground,
                    modifier = Modifier.size(24.dp),
                    strokeWidth = 2.5.dp
                )
            } else {
                Text(
                    text = "PAIR & CONNECT",
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp,
                    letterSpacing = 1.sp
                )
            }
        }
    }
}
