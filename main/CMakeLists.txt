# PlatformIO needs the main component in src_dir, which platformio.ini sets to main/.
# The firmware's app_main() lives in pico-keys-sdk/src/main.c. The source below only gives this
# component a translation unit, so the PlatformIO ESP-IDF build finds a main target.
idf_component_register(
    SRCS "pio_entry.c"
    INCLUDE_DIRS "."
    REQUIRES fido pico-keys-sdk
)
