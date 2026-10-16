# PlatformIO requires a main component in src/ (its default src_dir).
# The firmware's app_main() lives in pico-keys-sdk/src/main.c. The source below only gives this
# component a translation unit, so the PlatformIO ESP-IDF build finds a main target.
idf_component_register(
    SRCS "pio_entry.c"
    INCLUDE_DIRS "."
)
