find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(WG_OUTDIR "${CMAKE_SOURCE_DIR}")
set(ARG_DEFS  "${CMAKE_SOURCE_DIR}/argument_definitions.h.in")

add_custom_command(
  OUTPUT
    "${WG_OUTDIR}/argument_definitions.h"
    "${WG_OUTDIR}/wg0.conf"
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/gen_wireguard_artifacts.py"
          --outdir "${WG_OUTDIR}"
          --argument-definitions-h "${ARG_DEFS}"
          --net-config "${CMAKE_SOURCE_DIR}/net_config.yaml"
          --iface-type "${WG_IFACE_TYPE}"
          --require-all 0
  DEPENDS
    "${CMAKE_SOURCE_DIR}/tools/gen_wireguard_artifacts.py"
    "${ARG_DEFS}"
    "${CMAKE_SOURCE_DIR}/net_config.yaml"
  VERBATIM
)

add_custom_target(wireguard_artifacts ALL
  DEPENDS
    "${WG_OUTDIR}/wg0.conf"
    "${WG_OUTDIR}/argument_definitions.h"
)
