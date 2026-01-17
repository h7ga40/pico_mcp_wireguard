# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)

# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.1.1)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.1.1)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico CACHE STRING "Board type")
set(BOARD_NAME W55RP20_EVB_PICO)

# Set WIZchip Clock Speed
set(WIZCHIP_SPI_SCLK_SPEED 43)
add_definitions(-D_WIZCHIP_SPI_SCLK_SPEED=${WIZCHIP_SPI_SCLK_SPEED})

set(WIZNET_CHIP W5500)
add_definitions(-D_WIZCHIP_=W5500)
add_definitions(-DDEVICE_BOARD_NAME=W55RP20_EVB_PICO)
add_definitions(-DPICO_XOSC_STARTUP_DELAY_MULTIPLIER=64)

# Ensure required git submodules are present
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/.git")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        RESULT_VARIABLE GIT_SUBMOD_RESULT
    )
    if(NOT GIT_SUBMOD_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to update git submodules")
    endif()

    set(WIREGUARD_LWIP_PATCH ${CMAKE_CURRENT_LIST_DIR}/patches/wireguard-lwip-lwipopts.patch)
    if(EXISTS ${WIREGUARD_LWIP_PATCH})
        execute_process(
            COMMAND ${GIT_EXECUTABLE} -C ${CMAKE_CURRENT_LIST_DIR}/libraries/wireguard-lwip
                    apply --check ${WIREGUARD_LWIP_PATCH}
            RESULT_VARIABLE WIREGUARD_LWIP_PATCH_CHECK
        )
        if(WIREGUARD_LWIP_PATCH_CHECK EQUAL 0)
            execute_process(
                COMMAND ${GIT_EXECUTABLE} -C ${CMAKE_CURRENT_LIST_DIR}/libraries/wireguard-lwip
                        apply ${WIREGUARD_LWIP_PATCH}
                RESULT_VARIABLE WIREGUARD_LWIP_PATCH_RESULT
            )
            if(NOT WIREGUARD_LWIP_PATCH_RESULT EQUAL 0)
                message(FATAL_ERROR "Failed to apply wireguard-lwip lwipopts.h patch")
            endif()
        endif()
    endif()
endif()

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)
include(wiznet_pico_lwip_c_sdk_version.cmake)

project(pico_mcp C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

include(pico_wireguard_import.cmake)

set(WG_IFACE_TYPE "ethernets" CACHE STRING "Interface type for net_config.yaml (wifis or ethernets)")

# Set the project root directory if it's not already defined, as may happen if
# the tests folder is included directly by a parent project, without including
# the top level CMakeLists.txt.
if(NOT DEFINED WIZNET_DIR)
    set(WIZNET_DIR ${CMAKE_SOURCE_DIR}/libraries/ioLibrary_Driver)
    message(STATUS "WIZNET_DIR = ${WIZNET_DIR}")
endif()

if(NOT DEFINED PORT_DIR)
    set(PORT_DIR ${CMAKE_SOURCE_DIR}/port)
    message(STATUS "PORT_DIR = ${PORT_DIR}")
endif()

# Add libraries in subdirectories
add_subdirectory(${CMAKE_SOURCE_DIR}/libraries)
add_subdirectory(${PORT_DIR})

# Add executable. Default name is the project name, version 0.1
add_executable(pico_mcp 
    runtime_init_clocks.c
    pico_mcp.c
    usb_descriptors.c
    llhttp/llhttp.c
    llhttp/api.c
    llhttp/http.c
    parson/parson.c
)

pico_set_program_name(pico_mcp "pico_mcp")
pico_set_program_version(pico_mcp "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_uart(pico_mcp 1)
pico_enable_stdio_usb(pico_mcp 0)

# Add the standard library to the build
target_link_libraries(pico_mcp
    pico_stdlib
    pico_multicore
    pico_httpd_content
    hardware_spi
    hardware_dma
    tinyusb_device
    tinyusb_board
)

set(WIFI_SSID $ENV{WIFI_SSID})
set(WIFI_PASSWORD $ENV{WIFI_PASSWORD})

target_compile_definitions(pico_mcp PRIVATE
    USE_TINYUSB
    CFG_TUSB_RHPORT0_MODE
)

# Add the standard include files to the build
target_include_directories(pico_mcp PRIVATE
    ${PORT_DIR}/lwip
    ${pico_wireguard_SOURCE_DIR}/src
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/llhttp
    ${CMAKE_CURRENT_LIST_DIR}/parson
)

# Add any user requested libraries
target_link_libraries(pico_mcp 
    pico_wireguard
    pico_lwip_nosys
    ETHERNET_FILES
    IOLIBRARY_FILES
    LWIP_FILES
)

pico_add_extra_outputs(pico_mcp)

include(gen_wireguard_artifacts.cmake)
add_dependencies(pico_mcp wireguard_artifacts)

include(makefsdata.cmake)
pico_add_library(pico_httpd_content NOFLAG)
pico_mcp_set_lwip_httpd_content(pico_httpd_content INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/content/404.html
    ${CMAKE_CURRENT_LIST_DIR}/content/keyboard.html
    ${CMAKE_CURRENT_LIST_DIR}/content/wol.html
    ${CMAKE_CURRENT_LIST_DIR}/content/wol_allowlist.json
)
