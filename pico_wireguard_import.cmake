set(PICO_WIREGUARD_PATH libraries/wireguard-lwip)
message("Using PICO_WIREGUARD_PATH from environment ('${PICO_WIREGUARD_PATH}')")

add_subdirectory(${PICO_WIREGUARD_PATH} build/lib/pico_wireguard)
