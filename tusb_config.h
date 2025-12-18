#ifndef _TUSB_CONFIG_H_
#define _TUSB_CONFIG_H_

#ifdef __cplusplus
 extern "C" {
#endif

#define CFG_TUSB_MCU OPT_MCU_RP2040
#define CFG_TUSB_OS  OPT_OS_PICO

#define CFG_TUD_ENABLED 1
#define CFG_TUD_MAX_SPEED OPT_MODE_FULL_SPEED

// Device class drivers
#define CFG_TUD_HID  1
#define CFG_TUD_CDC  0
#define CFG_TUD_MSC  0
#define CFG_TUD_MIDI 0
#define CFG_TUD_VENDOR 0

// HID
#define CFG_TUD_HID_EP_BUFSIZE 16

#ifdef __cplusplus
 }
#endif

#endif
