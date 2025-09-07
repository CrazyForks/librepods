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

package me.kavishdevar.librepods.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowLeft
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import me.kavishdevar.librepods.R
import me.kavishdevar.librepods.composables.AccessibilitySlider
import me.kavishdevar.librepods.services.ServiceManager

import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EqualizerSettingsScreen(
    navController: NavController,
    leftEQ: MutableState<FloatArray>,
    rightEQ: MutableState<FloatArray>,
    singleMode: MutableState<Boolean>,
    onEQChanged: () -> Unit,
    phoneMediaEQ: MutableState<FloatArray>
) {
    val isDarkTheme = isSystemInDarkTheme()
    val backgroundColor = if (isDarkTheme) Color(0xFF000000) else Color(0xFFF2F2F7)
    val cardBackgroundColor = if (isDarkTheme) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)
    val textColor = if (isDarkTheme) Color.White else Color.Black

    val aacpManager = ServiceManager.getService()!!.aacpManager

    val debounceJob = remember { mutableStateOf<Job?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "Equalizer Settings",
                        style = TextStyle(
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Medium,
                            color = textColor,
                            fontFamily = androidx.compose.ui.text.font.FontFamily(
                                Font(R.font.sf_pro)
                            )
                        )
                    )
                },
                navigationIcon = {
                    TextButton(
                        onClick = { navController.popBackStack() },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.KeyboardArrowLeft,
                            contentDescription = "Back",
                            tint = if (isDarkTheme) Color(0xFF007AFF) else Color(0xFF3C6DF5),
                            modifier = Modifier.scale(1.5f)
                        )
                        Text(
                            "Accessibility",
                            style = TextStyle(
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Medium,
                                color = if (isDarkTheme) Color(0xFF007AFF) else Color(0xFF3C6DF5),
                                fontFamily = androidx.compose.ui.text.font.FontFamily(
                                    Font(R.font.sf_pro)
                                )
                            ),
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent
                )
            )
        },
        containerColor = backgroundColor
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            if (singleMode.value) {
                // Single Bud EQ Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = cardBackgroundColor),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            "Equalizer",
                            style = TextStyle(
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Medium,
                                color = textColor,
                                fontFamily = androidx.compose.ui.text.font.FontFamily(
                                    Font(R.font.sf_pro)
                                )
                            )
                        )

                        for (i in 0..7) {
                            AccessibilitySlider(
                                label = "EQ${i + 1}",
                                value = leftEQ.value[i],
                                onValueChange = {
                                    leftEQ.value = leftEQ.value.copyOf().apply { this[i] = it }
                                    rightEQ.value = rightEQ.value.copyOf().apply { this[i] = it }  // Sync to right
                                    onEQChanged()
                                },
                                valueRange = 0f..100f
                            )
                        }
                    }
                }
            } else {
                // Left Bud EQ Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = cardBackgroundColor),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            "Left Bud Equalizer",
                            style = TextStyle(
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Medium,
                                color = textColor,
                                fontFamily = androidx.compose.ui.text.font.FontFamily(
                                    Font(R.font.sf_pro)
                                )
                            )
                        )

                        for (i in 0..7) {
                            AccessibilitySlider(
                                label = "EQ${i + 1}",
                                value = leftEQ.value[i],
                                onValueChange = {
                                    leftEQ.value = leftEQ.value.copyOf().apply { this[i] = it }
                                    onEQChanged()
                                },
                                valueRange = 0f..100f
                            )
                        }
                    }
                }

                // Right Bud EQ Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = cardBackgroundColor),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            "Right Bud Equalizer",
                            style = TextStyle(
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Medium,
                                color = textColor,
                                fontFamily = androidx.compose.ui.text.font.FontFamily(
                                    Font(R.font.sf_pro)
                                )
                            )
                        )

                        for (i in 0..7) {
                            AccessibilitySlider(
                                label = "EQ${i + 1}",
                                value = rightEQ.value[i],
                                onValueChange = {
                                    rightEQ.value = rightEQ.value.copyOf().apply { this[i] = it }
                                    onEQChanged()
                                },
                                valueRange = 0f..100f
                            )
                        }
                    }
                }
            }

            // Phone and Media EQ Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardBackgroundColor),
                shape = RoundedCornerShape(14.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text(
                        "Phone and Media Equalizer",
                        style = TextStyle(
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Medium,
                            color = textColor,
                            fontFamily = androidx.compose.ui.text.font.FontFamily(
                                Font(R.font.sf_pro)
                            )
                        )
                    )

                    for (i in 0..7) {
                        AccessibilitySlider(
                            label = "EQ${i + 1}",
                            value = phoneMediaEQ.value[i],
                            onValueChange = {
                                phoneMediaEQ.value = phoneMediaEQ.value.copyOf().apply { this[i] = it }
                                debounceJob.value?.cancel()
                                debounceJob.value = CoroutineScope(Dispatchers.IO).launch {
                                    delay(100)
                                    aacpManager.sendPhoneMediaEQ(phoneMediaEQ.value)
                                }
                            },
                            valueRange = 0f..100f
                        )
                    }
                }
            }
        }
    }
}