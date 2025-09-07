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

package me.kavishdevar.librepods.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import me.kavishdevar.librepods.R
import me.kavishdevar.librepods.composables.AccessibilitySlider
import me.kavishdevar.librepods.composables.NavigationButton
import me.kavishdevar.librepods.composables.StyledSwitch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccessibilitySettingsScreen(
    navController: NavController,
    isConnected: Boolean,
    leftAmplification: MutableState<Float>,
    leftTone: MutableState<Float>,
    leftAmbientNoiseReduction: MutableState<Float>,
    leftConversationBoost: MutableState<Boolean>,
    rightAmplification: MutableState<Float>,
    rightTone: MutableState<Float>,
    rightAmbientNoiseReduction: MutableState<Float>,
    rightConversationBoost: MutableState<Boolean>,
    singleMode: MutableState<Boolean>,
    amplification: MutableState<Float>,
    balance: MutableState<Float>,
    showRetryButton: Boolean,
    onRetry: () -> Unit,
    onSettingsChanged: () -> Unit
) {
    val isDarkTheme = isSystemInDarkTheme()
    val backgroundColor = if (isDarkTheme) Color(0xFF000000) else Color(0xFFF2F2F7)
    val cardBackgroundColor = if (isDarkTheme) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)
    val textColor = if (isDarkTheme) Color.White else Color.Black

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "Accessibility Settings",
                        style = TextStyle(
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Medium,
                            color = textColor,
                            fontFamily = androidx.compose.ui.text.font.FontFamily(Font(R.font.sf_pro))
                        )
                    )
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
            // Retry Button if needed
            if (!isConnected && showRetryButton) {
                Button(
                    onClick = onRetry,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF007AFF)
                    )
                ) {
                    Text("Retry Connection")
                }
            }

            // Single Mode Switch
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardBackgroundColor),
                shape = RoundedCornerShape(14.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        "Single Mode",
                        style = TextStyle(
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Medium,
                            color = textColor,
                            fontFamily = androidx.compose.ui.text.font.FontFamily(Font(R.font.sf_pro))
                        )
                    )
                    StyledSwitch(
                        checked = singleMode.value,
                        onCheckedChange = {
                            singleMode.value = it
                            if (it) {
                                // When switching to single mode, set amplification and balance
                                val avg = (leftAmplification.value + rightAmplification.value) / 2
                                amplification.value = avg.coerceIn(0f, 1f)
                                val diff = rightAmplification.value - leftAmplification.value
                                balance.value = (0.5f + diff / (2 * avg)).coerceIn(0f, 1f)
                                // Update left and right
                                val amp = amplification.value
                                val bal = balance.value
                                leftAmplification.value = amp * (1 + bal)
                                rightAmplification.value = amp * (2 - bal)
                            }
                        }
                    )
                }
            }

            if (isConnected) {
                if (singleMode.value) {
                    // Balance Slider for Amplification
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
                            AccessibilitySlider(
                                label = "Amplification",
                                value = amplification.value,
                                onValueChange = {
                                    amplification.value = it
                                    val amp = it
                                    val bal = balance.value
                                    leftAmplification.value = amp * (1 + bal)
                                    rightAmplification.value = amp * (2 - bal)
                                    onSettingsChanged()
                                },
                                valueRange = 0f..1f
                            )

                            AccessibilitySlider(
                                label = "Balance",
                                value = balance.value,
                                onValueChange = {
                                    balance.value = it
                                    val amp = amplification.value
                                    val bal = it
                                    leftAmplification.value = amp * (1 + bal)
                                    rightAmplification.value = amp * (2 - bal)
                                    onSettingsChanged()
                                },
                                valueRange = 0f..1f
                            )
                        }
                    }

                    // Single Bud Settings Card
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
                                "Bud Settings",
                                style = TextStyle(
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = textColor,
                                    fontFamily = androidx.compose.ui.text.font.FontFamily(
                                        Font(R.font.sf_pro)
                                    )
                                )
                            )

                            AccessibilitySlider(
                                label = "Tone",
                                value = leftTone.value,
                                onValueChange = {
                                    leftTone.value = it
                                    rightTone.value = it
                                    onSettingsChanged()
                                },
                                valueRange = 0f..2f
                            )

                            AccessibilitySlider(
                                label = "Ambient Noise Reduction",
                                value = leftAmbientNoiseReduction.value,
                                onValueChange = {
                                    leftAmbientNoiseReduction.value = it
                                    rightAmbientNoiseReduction.value = it
                                    onSettingsChanged()
                                },
                                valueRange = 0f..1f
                            )

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    "Conversation Boost",
                                    style = TextStyle(
                                        fontSize = 16.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = textColor,
                                        fontFamily = androidx.compose.ui.text.font.FontFamily(
                                            Font(R.font.sf_pro)
                                        )
                                    )
                                )
                                StyledSwitch(
                                    checked = leftConversationBoost.value,
                                    onCheckedChange = {
                                        leftConversationBoost.value = it
                                        rightConversationBoost.value = it
                                        onSettingsChanged()
                                    }
                                )
                            }

                            NavigationButton(
                                to = "eq",
                                name = "Equalizer Settings",
                                navController = navController
                            )
                        }
                    }
                } else {
                    // Left Bud Card
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
                                "Left Bud",
                                style = TextStyle(
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = textColor,
                                    fontFamily = androidx.compose.ui.text.font.FontFamily(
                                        Font(R.font.sf_pro)
                                    )
                                )
                            )

                            AccessibilitySlider(
                                label = "Amplification",
                                value = leftAmplification.value,
                                onValueChange = {
                                    leftAmplification.value = it
                                    onSettingsChanged()
                                },
                                valueRange = 0f..2f
                            )

                            AccessibilitySlider(
                                label = "Tone",
                                value = leftTone.value,
                                onValueChange = {
                                    leftTone.value = it
                                    onSettingsChanged()
                                },
                                valueRange = 0f..2f
                            )

                            AccessibilitySlider(
                                label = "Ambient Noise Reduction",
                                value = leftAmbientNoiseReduction.value,
                                onValueChange = {
                                    leftAmbientNoiseReduction.value = it
                                    onSettingsChanged()
                                },
                                valueRange = 0f..1f
                            )

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    "Conversation Boost",
                                    style = TextStyle(
                                        fontSize = 16.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = textColor,
                                        fontFamily = androidx.compose.ui.text.font.FontFamily(
                                            Font(R.font.sf_pro)
                                        )
                                    )
                                )
                                StyledSwitch(
                                    checked = leftConversationBoost.value,
                                    onCheckedChange = {
                                        leftConversationBoost.value = it
                                        onSettingsChanged()
                                    }
                                )
                            }

                            NavigationButton(
                                to = "eq",
                                name = "Equalizer Settings",
                                navController = navController
                            )
                        }
                    }

                    // Right Bud Card
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
                                "Right Bud",
                                style = TextStyle(
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = textColor,
                                    fontFamily = androidx.compose.ui.text.font.FontFamily(
                                        Font(R.font.sf_pro)
                                    )
                                )
                            )

                            AccessibilitySlider(
                                label = "Amplification",
                                value = rightAmplification.value,
                                onValueChange = {
                                    rightAmplification.value = it
                                    onSettingsChanged()
                                },
                                valueRange = 0f..2f
                            )

                            AccessibilitySlider(
                                label = "Tone",
                                value = rightTone.value,
                                onValueChange = {
                                    rightTone.value = it
                                    onSettingsChanged()
                                },
                                valueRange = 0f..2f
                            )

                            AccessibilitySlider(
                                label = "Ambient Noise Reduction",
                                value = rightAmbientNoiseReduction.value,
                                onValueChange = {
                                    rightAmbientNoiseReduction.value = it
                                    onSettingsChanged()
                                },
                                valueRange = 0f..1f
                            )

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    "Conversation Boost",
                                    style = TextStyle(
                                        fontSize = 16.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = textColor,
                                        fontFamily = androidx.compose.ui.text.font.FontFamily(
                                            Font(R.font.sf_pro)
                                        )
                                    )
                                )
                                StyledSwitch(
                                    checked = rightConversationBoost.value,
                                    onCheckedChange = {
                                        rightConversationBoost.value = it
                                        onSettingsChanged()
                                    }
                                )
                            }

                            NavigationButton(
                                to = "eq",
                                name = "Equalizer Settings",
                                navController = navController
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}