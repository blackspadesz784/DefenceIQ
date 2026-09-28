package com.defenceiq.app.ui.history

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.defenceiq.app.data.QuarantinedFile
import com.defenceiq.app.network.DefenceIqRepository
import com.defenceiq.app.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun QuarantineScreen(
    repository: DefenceIqRepository
) {
    val quarantinedFiles by repository.quarantinedFiles.collectAsState()
    val coroutineScope = rememberCoroutineScope()
    var restoringId by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(LightBackground)
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Quarantine Vault",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary
                )
                Text(
                    text = "Isolated suspicious files & reversible rollback",
                    fontSize = 12.sp,
                    color = TextSecondary
                )
            }

            IconButton(
                onClick = {
                    coroutineScope.launch { repository.refreshQuarantine() }
                }
            ) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = PrimaryBlue)
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        if (quarantinedFiles.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Default.FolderOpen,
                        contentDescription = null,
                        tint = TextMuted,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "Quarantine Vault is Empty",
                        color = TextPrimary,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "No suspicious files are currently quarantined.",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                }
            }
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(quarantinedFiles, key = { it.quarantineId }) { file ->
                    QuarantineItemCard(
                        file = file,
                        isRestoring = restoringId == file.quarantineId,
                        onRestore = {
                            restoringId = file.quarantineId
                            coroutineScope.launch {
                                repository.restoreQuarantinedFile(file.quarantineId)
                                restoringId = null
                            }
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun QuarantineItemCard(
    file: QuarantinedFile,
    isRestoring: Boolean,
    onRestore: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = LightSurface),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, LightBorderColor, RoundedCornerShape(12.dp))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = file.originalName,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary
                )

                if (file.restored) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(BandGreen.copy(alpha = 0.1f))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = "RESTORED",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = BandGreen
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Original Path: ${file.originalPath}",
                fontSize = 11.sp,
                color = TextSecondary
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Reason: ${file.reason}",
                fontSize = 12.sp,
                color = BandOrange
            )

            Spacer(modifier = Modifier.height(10.dp))

            if (!file.restored) {
                Button(
                    onClick = onRestore,
                    enabled = !isRestoring,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = PrimaryBlue,
                        contentColor = Color.White
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (isRestoring) {
                        CircularProgressIndicator(
                            color = Color.White,
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(Icons.Default.Restore, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "RESTORE FILE (UNDO)",
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }
            }
        }
    }
}
