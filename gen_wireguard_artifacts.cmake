find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(WG_OUTDIR "${CMAKE_SOURCE_DIR}")
set(ARG_DEFS  "${CMAKE_SOURCE_DIR}/argument_definitions.h.in")

add_custom_command(
  OUTPUT
    "${WG_OUTDIR}/argument_definitions.h"
    "${WG_OUTDIR}/wg0.conf"
    "${WG_OUTDIR}/pico.key" "${WG_OUTDIR}/pico.pub"
    "${WG_OUTDIR}/pc.key"   "${WG_OUTDIR}/pc.pub"
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/gen_wireguard_artifacts.py"
          --outdir "${WG_OUTDIR}"
          --argument-definitions-h "${ARG_DEFS}"
          --pico-lan-ip "192.168.1.50"
          --pico-listen-port 51820
          --pc-tunnel-ip "10.7.0.1"
          --pico-tunnel-ip "10.7.0.2"
          --allowed-ips "10.7.0.2/24"
          --require-all 0
  DEPENDS
    "${CMAKE_SOURCE_DIR}/tools/gen_wireguard_artifacts.py"
    "${ARG_DEFS}"
  VERBATIM
)

add_custom_target(wireguard_artifacts ALL
  DEPENDS
    "${WG_OUTDIR}/wg0.conf"
    "${WG_OUTDIR}/pico.key" "${WG_OUTDIR}/pico.pub"
    "${WG_OUTDIR}/pc.key"   "${WG_OUTDIR}/pc.pub"
)
