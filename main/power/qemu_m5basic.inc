// Ruby: power management of the emulated M5Stack Basic (qemu).
// The real board (IP5306, power/ip5306.inc) is emulated on USB power with a full battery, so the screens, the
// battery icon, the version info and the idle-timeout (reboot to lock on USB power) are those of the real board.
// Turning it off (Sleep) restarts the emulator: the same as switching the real board off and on again.
#include <esp_system.h>

esp_err_t power_init(void) { return ESP_OK; }

esp_err_t power_shutdown(void)
{
    esp_restart();
    return ESP_OK;
}

esp_err_t power_screen_on(void) { return ESP_OK; }

esp_err_t power_backlight_on(const uint8_t brightness) { return ESP_OK; }
esp_err_t power_backlight_off(void) { return ESP_OK; }

esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

// IP5306 values for a full battery (power/ip5306.inc: 4150 mV, level 5, not charging when full)
uint16_t power_get_vbat(void) { return 4150; }
uint8_t power_get_battery_status(void) { return 5; }
bool power_get_battery_charging(void) { return false; }
uint16_t power_get_ibat_charge(void) { return 0; }
uint16_t power_get_ibat_discharge(void) { return 0; }
uint16_t power_get_vusb(void) { return 0; }
uint16_t power_get_iusb(void) { return 0; }
uint16_t power_get_temp(void) { return 0; }

bool usb_is_powered(void) { return true; }
