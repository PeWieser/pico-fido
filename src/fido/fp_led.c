/*
 * Pico FIDO - status LED integration for the R558 fingerprint feature.
 *
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Architecture note:
 *  1. The GROW R558-S sensor contains its own integrated multi-colour RGB ring LED controlled
 *     directly over UART via PS_ControlBLN (0x3C) in fp_r558.c.
 *  2. The ESP32-S3 board's own onboard RGB LED (GPIO48 / PHY-configured pin, driven by
 *     pico-keys-sdk's led_driver_neopixel via ESP-IDF RMT) MUST stay active for normal Pico-Fido
 *     idle heartbeat, USB activity and FIDO status blinks, while reflecting active fingerprint states.
 *  3. An optional external WS2812 ring on FP_LED_GPIO is only initialised when FP_EXTERNAL_NEOPIXEL_RING=1
 *     is explicitly enabled at compile time.
 */

#include "picokeys.h"
#include "led/led.h"
#include "fp_led.h"
#include "fp_r558_config.h"

#if defined(ESP_PLATFORM) && defined(ENABLE_R558_FINGERPRINT)

#include "compat/esp_compat.h"

#if defined(FP_EXTERNAL_NEOPIXEL_RING) && FP_EXTERNAL_NEOPIXEL_RING
#include "neopixel.h"
static tNeopixelContext ring = NULL;
static tNeopixel ring_pixels[FP_LED_COUNT];
#endif

static led_driver_t *prev_led_driver = NULL;
static volatile bool requesting = false;
static volatile bool saving = false;
static volatile bool enrolling = false;
static volatile uint8_t result = 0;          /* 0 none, 1 success, 2 failure */
static volatile uint32_t result_until = 0;

void fp_led_op_begin(void) {
    result = 0;
    requesting = true;
}

void fp_led_op_end(bool ok) {
    requesting = false;
    result = ok ? 1 : 2;
    result_until = board_millis() + FP_LED_RESULT_MS;
}

void fp_led_saving(bool on) {
    saving = on;
}

void fp_led_enrolling(bool on) {
    enrolling = on;
}

#if defined(FP_EXTERNAL_NEOPIXEL_RING) && FP_EXTERNAL_NEOPIXEL_RING
static uint32_t ring_rgb(uint8_t r, uint8_t g, uint8_t b) {
    switch (phy_data.led_order) {
        case PHY_LED_ORDER_RBG:
            return NP_RGB(r, b, g);
        case PHY_LED_ORDER_GRB:
            return NP_RGB(g, r, b);
        case PHY_LED_ORDER_GBR:
            return NP_RGB(g, b, r);
        case PHY_LED_ORDER_BRG:
            return NP_RGB(b, r, g);
        case PHY_LED_ORDER_BGR:
            return NP_RGB(b, g, r);
        case PHY_LED_ORDER_RGB:
        default:
            return NP_RGB(r, g, b);
    }
}
#endif

static void fp_chain_init(void) {
#if defined(FP_EXTERNAL_NEOPIXEL_RING) && FP_EXTERNAL_NEOPIXEL_RING
    ring = neopixel_Init(FP_LED_COUNT, FP_LED_GPIO);
    for (int i = 0; i < FP_LED_COUNT; i++) {
        ring_pixels[i].index = (uint16_t)i;
        ring_pixels[i].rgb = ring_rgb(0, 0, 0);
    }
#endif
}

static void fp_chain_set_color(uint8_t color, uint32_t led_brightness, float progress) {
    uint32_t now = board_millis();
    bool override_active = true;
    uint8_t ov_color = color;
    float ov_progress = progress;

    if (saving) {
        uint32_t phase = now % FP_LED_PULSE_PERIOD_MS;
        float x = (float)phase / (float)FP_LED_PULSE_PERIOD_MS;
        ov_progress = x < 0.5f ? 2.0f * x : 2.0f * (1.0f - x);
        ov_color = LED_COLOR_BLUE;
    }
    else if (enrolling) {
        uint32_t phase = now % FP_LED_BREATH_PERIOD_MS;
        float x = (float)phase / (float)FP_LED_BREATH_PERIOD_MS;
        ov_progress = 0.2f + 0.8f * (x < 0.5f ? 2.0f * x : 2.0f * (1.0f - x));
        ov_color = LED_COLOR_BLUE;
    }
    else if (result != 0 && now < result_until) {
        ov_color = (result == 1) ? LED_COLOR_GREEN : LED_COLOR_RED;
        ov_progress = 1.0f;
    }
    else if (requesting) {
        ov_color = LED_COLOR_BLUE;
        ov_progress = 1.0f;
    }
    else {
        result = 0;
        override_active = false;
    }

    if (prev_led_driver != NULL && prev_led_driver->set_color != NULL) {
        if (override_active) {
            prev_led_driver->set_color(ov_color, led_brightness > 0 ? led_brightness : MAX_BTNESS, ov_progress);
        }
        else {
            prev_led_driver->set_color(color, led_brightness, progress);
        }
    }

#if defined(FP_EXTERNAL_NEOPIXEL_RING) && FP_EXTERNAL_NEOPIXEL_RING
    if (ring != NULL) {
        uint8_t r = 0, g = 0, b = 0;
        if (override_active) {
            uint8_t scale = (uint8_t)(255.0f * ov_progress);
            if (ov_color == LED_COLOR_GREEN) {
                g = scale;
            }
            else if (ov_color == LED_COLOR_RED) {
                r = scale;
            }
            else {
                b = scale;
            }
        }
        uint32_t rgb = ring_rgb(r, g, b);
        for (int i = 0; i < FP_LED_COUNT; i++) {
            ring_pixels[i].rgb = rgb;
        }
        neopixel_SetPixel(ring, ring_pixels, FP_LED_COUNT);
    }
#endif
}

static led_driver_t fp_chain_driver = {
    .init = fp_chain_init,
    .set_color = fp_chain_set_color,
};

void fp_led_init(void) {
    if (led_driver != &fp_chain_driver) {
        prev_led_driver = led_driver;
        led_driver = &fp_chain_driver;
    }
    fp_chain_driver.init();
}

#else /* feature disabled or not an ESP32 build */

void fp_led_init(void) {
}

void fp_led_op_begin(void) {
}

void fp_led_op_end(bool ok) {
    (void)ok;
}

void fp_led_saving(bool on) {
    (void)on;
}

void fp_led_enrolling(bool on) {
    (void)on;
}

#endif
