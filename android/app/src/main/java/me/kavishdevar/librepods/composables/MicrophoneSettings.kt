/*
 * LibrePods - AirPods liberated from Apple’s ecosystem
 *
 * Copyright (C) 2025 LibrePods contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

@file:OptIn(ExperimentalEncodingApi::class)

package me.kavishdevar.librepods.composables

import android.util.Log
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import me.kavishdevar.librepods.R
import me.kavishdevar.librepods.services.ServiceManager
import me.kavishdevar.librepods.utils.AACPManager
import kotlin.io.encoding.ExperimentalEncodingApi

@Composable
fun MicrophoneSettings() {
    val isDarkTheme = isSystemInDarkTheme()
    val textColor = if (isDarkTheme) Color.White else Color.Black
    val backgroundColor = if (isDarkTheme) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(backgroundColor, RoundedCornerShape(14.dp))
            .padding(top = 2.dp)
    ) {
        val service = ServiceManager.getService()!!
        val micModeValue = service.aacpManager.controlCommandStatusList.find {
            it.identifier == AACPManager.Companion.ControlCommandIdentifiers.MIC_MODE
        }?.value?.get(0) ?: 0x00.toByte()
        
        var selectedMode by remember { 
            mutableStateOf(
                when (micModeValue) {
                    0x00.toByte() -> "Automatic"
                    0x01.toByte() -> "Always Right"
                    0x02.toByte() -> "Always Left"
                    else -> "Automatic"
                }
            )
        }
        var showDropdown by remember { mutableStateOf(false) }
        
        val listener = object : AACPManager.ControlCommandListener {
                override fun onControlCommandReceived(controlCommand: AACPManager.ControlCommand) {
                    if (AACPManager.Companion.ControlCommandIdentifiers.fromByte(controlCommand.identifier) == 
                        AACPManager.Companion.ControlCommandIdentifiers.MIC_MODE) {
                        selectedMode = when (controlCommand.value.get(0)) {
                            0x00.toByte() -> "Automatic"
                            0x01.toByte() -> "Always Right"
                            0x02.toByte() -> "Always Left"
                            else -> "Automatic"
                        }
                        Log.d("MicrophoneSettings", "Microphone mode received: $selectedMode")
                    }
                }
            }
            
        LaunchedEffect(Unit) {
            service.aacpManager.registerControlCommandListener(
                AACPManager.Companion.ControlCommandIdentifiers.MIC_MODE,
                listener
            )
        }

        DisposableEffect(Unit) {
            onDispose {
                service.aacpManager.unregisterControlCommandListener(
                    AACPManager.Companion.ControlCommandIdentifiers.MIC_MODE,
                    listener
                )
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, end = 12.dp)
                .height(55.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(R.string.microphone_mode),
                fontSize = 16.sp,
                color = textColor,
                modifier = Modifier.padding(bottom = 4.dp)
            )
            Box {
                Row(
                    modifier = Modifier.clickable { showDropdown = true },
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = selectedMode,
                        fontSize = 16.sp,
                        color = textColor.copy(alpha = 0.8f)
                    )
                    Icon(
                        Icons.Default.KeyboardArrowDown,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = textColor.copy(alpha = 0.6f)
                    )
                }
                DropdownMenu(
                    expanded = showDropdown,
                    onDismissRequest = { showDropdown = false }
                ) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.microphone_automatic)) },
                        onClick = {
                            selectedMode = "Automatic"
                            showDropdown = false
                            service.aacpManager.sendControlCommand(
                                AACPManager.Companion.ControlCommandIdentifiers.MIC_MODE.value,
                                byteArrayOf(0x00)
                            )
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.microphone_always_right)) },
                        onClick = {
                            selectedMode = "Always Right"
                            showDropdown = false
                            service.aacpManager.sendControlCommand(
                                AACPManager.Companion.ControlCommandIdentifiers.MIC_MODE.value,
                                byteArrayOf(0x01)
                            )
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.microphone_always_left)) },
                        onClick = {
                            selectedMode = "Always Left"
                            showDropdown = false
                            service.aacpManager.sendControlCommand(
                                AACPManager.Companion.ControlCommandIdentifiers.MIC_MODE.value,
                                byteArrayOf(0x02)
                            )
                        }
                    )
                }
            }
        }
    }
}

@Preview
@Composable
fun MicrophoneSettingsPreview() {
    MicrophoneSettings()
}