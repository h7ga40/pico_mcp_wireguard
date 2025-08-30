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
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico CACHE STRING "Board type")
set(BOARD_NAME W55RP20_EVB_PICO)
set(WIZNET_CHIP W5500)
add_definitions(-D_WIZCHIP_=W5500)
add_definitions(-DDEVICE_BOARD_NAME=W55RP20_EVB_PICO)

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)
include(wiznet_pico_lwip_c_sdk_version.cmake)

project(pico_mcp C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

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
    pico_mcp.c
    llhttp/llhttp.c
    llhttp/api.c
    llhttp/http.c
    parson/parson.c
)

pico_set_program_name(pico_mcp "pico_mcp")
pico_set_program_version(pico_mcp "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_uart(pico_mcp 0)
pico_enable_stdio_usb(pico_mcp 1)

# Add the standard library to the build
target_link_libraries(pico_mcp
    pico_stdlib
    hardware_spi
    hardware_dma
)

set(WIFI_SSID $ENV{WIFI_SSID})
set(WIFI_PASSWORD $ENV{WIFI_PASSWORD})

# Add the standard include files to the build
target_include_directories(pico_mcp PRIVATE
    ${PORT_DIR}/lwip
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/llhttp
    ${CMAKE_CURRENT_LIST_DIR}/parson
)

# Add any user requested libraries
target_link_libraries(pico_mcp 
    pico_lwip_nosys
    ETHERNET_FILES
    IOLIBRARY_FILES
    LWIP_FILES
)

pico_add_extra_outputs(pico_mcp)

