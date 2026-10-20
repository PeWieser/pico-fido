idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS .
    REQUIRES esp_tinyusb mbedtls efuse driver bootloader_support pico-keys-sdk
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
target_link_options(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=is_req_button_pending")
