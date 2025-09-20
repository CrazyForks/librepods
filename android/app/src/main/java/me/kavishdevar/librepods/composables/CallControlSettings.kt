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
fun CallControlSettings() {
    val isDarkTheme = isSystemInDarkTheme()
    val textColor = if (isDarkTheme) Color.White else Color.Black
    val backgroundColor = if (isDarkTheme) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)

    Text(
        text = stringResource(R.string.call_controls).uppercase(),
        style = TextStyle(
            fontSize = 14.sp,
            fontWeight = FontWeight.Light,
            color = textColor.copy(alpha = 0.6f)
        ),
        modifier = Modifier.padding(8.dp, bottom = 2.dp)
    )

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(backgroundColor, RoundedCornerShape(14.dp))
            .padding(top = 2.dp)
    ) {
        val service = ServiceManager.getService()!!
        val callControlEnabledValue = service.aacpManager.controlCommandStatusList.find {
            it.identifier == AACPManager.Companion.ControlCommandIdentifiers.CALL_MANAGEMENT_CONFIG
        }?.value ?: byteArrayOf(0x00, 0x03)
        
        var flipped by remember { mutableStateOf(callControlEnabledValue.contentEquals(byteArrayOf(0x00, 0x02))) }
        var singlePressAction by remember { mutableStateOf(if (flipped) "Press Twice" else "Press Once") }
        var doublePressAction by remember { mutableStateOf(if (flipped) "Press Once" else "Press Twice") }
        var showSinglePressDropdown by remember { mutableStateOf(false) }
        var showDoublePressDropdown by remember { mutableStateOf(false) }

        LaunchedEffect(Unit) {
            val listener = object : AACPManager.ControlCommandListener {
                override fun onControlCommandReceived(controlCommand: AACPManager.ControlCommand) {
                    if (AACPManager.Companion.ControlCommandIdentifiers.fromByte(controlCommand.identifier) == 
                        AACPManager.Companion.ControlCommandIdentifiers.CALL_MANAGEMENT_CONFIG) {
                        val newFlipped = controlCommand.value.contentEquals(byteArrayOf(0x00, 0x02))
                        flipped = newFlipped
                        singlePressAction = if (newFlipped) "Press Twice" else "Press Once"
                        doublePressAction = if (newFlipped) "Press Once" else "Press Twice"
                        Log.d("CallControlSettings", "Control command received, flipped: $newFlipped")
                    }
                }
            }
            
            service.aacpManager.registerControlCommandListener(
                AACPManager.Companion.ControlCommandIdentifiers.CALL_MANAGEMENT_CONFIG,
                listener
            )
        }

        DisposableEffect(Unit) {
            onDispose {
                service.aacpManager.controlCommandListeners[AACPManager.Companion.ControlCommandIdentifiers.CALL_MANAGEMENT_CONFIG]?.clear()
            }
        }

        LaunchedEffect(flipped) {
            Log.d("CallControlSettings", "Call control flipped: $flipped")
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 12.dp, end = 12.dp)
                    .height(50.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.answer_call),
                    fontSize = 16.sp,
                    color = textColor,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Text(
                    text = stringResource(R.string.press_once),
                    fontSize = 16.sp,
                    color = textColor.copy(alpha = 0.6f)
                )
            }
            HorizontalDivider(
                thickness = 1.5.dp,
                color = Color(0x40888888),
                modifier = Modifier
                    .padding(start = 12.dp, end = 0.dp)
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 12.dp, end = 12.dp)
                    .height(50.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.mute_unmute),
                    fontSize = 16.sp,
                    color = textColor,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Box {
                    Row(
                        modifier = Modifier.clickable { showSinglePressDropdown = true },
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (singlePressAction == "Press Once") stringResource(R.string.press_once) else stringResource(R.string.press_twice),
                            fontSize = 16.sp,
                            color = textColor.copy(alpha = 0.8f)
                        )
                        Icon(
                            Icons.Default.KeyboardArrowDown,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                            tint = textColor.copy(alpha = 0.6f)
                        )
                    }
                    DropdownMenu(
                        expanded = showSinglePressDropdown,
                        onDismissRequest = { showSinglePressDropdown = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.press_once)) },
                            onClick = {
                                singlePressAction = "Press Once"
                                doublePressAction = "Press Twice"
                                showSinglePressDropdown = false
                                service.aacpManager.sendControlCommand(0x24, byteArrayOf(0x00, 0x03))
                            }
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.press_twice)) },
                            onClick = {
                                singlePressAction = "Press Twice"
                                doublePressAction = "Press Once"
                                showSinglePressDropdown = false
                                service.aacpManager.sendControlCommand(0x24, byteArrayOf(0x00, 0x02))
                            }
                        )
                    }
                }
            }
            HorizontalDivider(
                thickness = 1.5.dp,
                color = Color(0x40888888),
                modifier = Modifier
                    .padding(start = 12.dp, end = 0.dp)
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 12.dp, end = 12.dp)
                    .height(50.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.hang_up),
                    fontSize = 16.sp,
                    color = textColor,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Box {
                    Row(
                        modifier = Modifier.clickable { showDoublePressDropdown = true },
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (doublePressAction == "Press Once") stringResource(R.string.press_once) else stringResource(R.string.press_twice),
                            fontSize = 16.sp,
                            color = textColor.copy(alpha = 0.8f)
                        )
                        Icon(
                            Icons.Default.KeyboardArrowDown,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                            tint = textColor.copy(alpha = 0.6f)
                        )
                    }
                    DropdownMenu(
                        expanded = showDoublePressDropdown,
                        onDismissRequest = { showDoublePressDropdown = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.press_once)) },
                            onClick = {
                                doublePressAction = "Press Once"
                                singlePressAction = "Press Twice"
                                showDoublePressDropdown = false
                                service.aacpManager.sendControlCommand(0x24, byteArrayOf(0x00, 0x02))
                            }
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.press_twice)) },
                            onClick = {
                                doublePressAction = "Press Twice"
                                singlePressAction = "Press Once"
                                showDoublePressDropdown = false
                                service.aacpManager.sendControlCommand(0x24, byteArrayOf(0x00, 0x03))
                            }
                        )
                    }
                }
            }
        }
    }
}

@Preview
@Composable
fun CallControlSettingsPreview() {
    CallControlSettings()
}