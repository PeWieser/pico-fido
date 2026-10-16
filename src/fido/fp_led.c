/*
 * Pico FIDO - status ring for the R558 fingerprint feature.
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
 */

#include "picokeys.h"
#include "led/led.h"
#include "fp_led.h"
#include "fp_r558_config.h"

#if defined(ESP_PLATFORM) && defined(ENABLE_R558_FINGERPRINT)

#include "neopixel.h"
#include "compat/esp_compat.h"

static tNeopixelContext ring = NULL;
static tNeopixel ring_pixels[FP_LED_COUNT];

static volatile bool requesting = false;
static volatile bool saving = false;
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

/* Same colour order mapping as led_neopixel.c, so the PHY LED order setting applies to the ring too. */
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

static void ring_init(void) {
    ring = neopixel_Init(FP_LED_COUNT, FP_LED_GPIO);
    for (int i = 0; i < FP_LED_COUNT; i++) {
        ring_pixels[i].index = (uint16_t)i;
        ring_pixels[i].rgb = ring_rgb(0, 0, 0);
    }
}

/* The ring ignores the mode bits of the generic LED engine: it only shows the fingerprint states. */
static void ring_set_color(uint8_t color, uint32_t led_brightness, float progress) {
    (void)color;
    (void)led_brightness;
    (void)progress;

    uint8_t r = 0, g = 0, b = 0;
    uint32_t now = board_millis();

    if (saving) {
        uint32_t phase = now % FP_LED_PULSE_PERIOD_MS;
        float x = (float)phase / (float)FP_LED_PULSE_PERIOD_MS;      /* 0..1 */
        float tri = x < 0.5f ? 2.0f * x : 2.0f * (1.0f - x);          /* triangle 0..1..0 */
        b = (uint8_t)(20.0f + 235.0f * tri);
    }
    else if (result != 0 && now < result_until) {
        if (result == 1) {
            g = 255;
        }
        else {
            r = 255;
        }
    }
    else if (requesting) {
        b = 255;
    }
    else {
        result = 0;
    }

    uint32_t rgb = ring_rgb(r, g, b);
    for (int i = 0; i < FP_LED_COUNT; i++) {
        ring_pixels[i].rgb = rgb;
    }
    neopixel_SetPixel(ring, ring_pixels, FP_LED_COUNT);
}

static led_driver_t fp_ring_driver = {
    .init = ring_init,
    .set_color = ring_set_color,
};

void fp_led_init(void) {
    led_driver = &fp_ring_driver;
    led_driver->init();
}

#else /* feature disabled or not an ESP32 build: no status ring */

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

#endif
