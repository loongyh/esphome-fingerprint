#pragma once

#include "esphome/core/component.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/uart/uart.h"

namespace esphome {
namespace fingerprint_reader {

// Based on Adafruit's library: https://github.com/adafruit/Adafruit-Fingerprint-Sensor-Library

#define FINGERPRINT_OK 0x00
#define FINGERPRINT_PACKETRECIEVEERR 0x01
#define FINGERPRINT_NOFINGER 0x02
#define FINGERPRINT_IMAGEFAIL 0x03
#define FINGERPRINT_IMAGEMESS 0x06
#define FINGERPRINT_FEATUREFAIL 0x07
#define FINGERPRINT_NOMATCH 0x08
#define FINGERPRINT_NOTFOUND 0x09
#define FINGERPRINT_ENROLLMISMATCH 0x0A
#define FINGERPRINT_BADLOCATION 0x0B
#define FINGERPRINT_DBRANGEFAIL 0x0C
#define FINGERPRINT_UPLOADFEATUREFAIL 0x0D
#define FINGERPRINT_PACKETRESPONSEFAIL 0x0E
#define FINGERPRINT_UPLOADFAIL 0x0F
#define FINGERPRINT_DELETEFAIL 0x10
#define FINGERPRINT_DBCLEARFAIL 0x11
#define FINGERPRINT_PASSFAIL 0x13
#define FINGERPRINT_INVALIDIMAGE 0x15
#define FINGERPRINT_FLASHERR 0x18
#define FINGERPRINT_INVALIDREG 0x1A
#define FINGERPRINT_ADDRCODE 0x20
#define FINGERPRINT_PASSVERIFY 0x21
#define FINGERPRINT_STARTCODE 0xEF01

#define FINGERPRINT_COMMANDPACKET 0x1
#define FINGERPRINT_DATAPACKET 0x2
#define FINGERPRINT_ACKPACKET 0x7
#define FINGERPRINT_ENDDATAPACKET 0x8

#define FINGERPRINT_TIMEOUT 0xFF
#define FINGERPRINT_BADPACKET 0xFE

#define FINGERPRINT_GETIMAGE 0x01
#define FINGERPRINT_IMAGE2TZ 0x02
#define FINGERPRINT_SEARCH 0x04
#define FINGERPRINT_REGMODEL 0x05
#define FINGERPRINT_STORE 0x06
#define FINGERPRINT_LOAD 0x07
#define FINGERPRINT_UPLOAD 0x08
#define FINGERPRINT_DELETE 0x0C
#define FINGERPRINT_EMPTY 0x0D
#define FINGERPRINT_READSYSPARAM 0x0F
#define FINGERPRINT_SETPASSWORD 0x12
#define FINGERPRINT_VERIFYPASSWORD 0x13
#define FINGERPRINT_HISPEEDSEARCH 0x1B
#define FINGERPRINT_TEMPLATECOUNT 0x1D
#define FINGERPRINT_AURALEDCONFIG 0x35
#define FINGERPRINT_LEDON 0x50
#define FINGERPRINT_LEDOFF 0x51

#define FINGERPRINT_LED_BREATHING 0x01
#define FINGERPRINT_LED_FLASHING 0x02
#define FINGERPRINT_LED_ON 0x03
#define FINGERPRINT_LED_OFF 0x04
#define FINGERPRINT_LED_GRADUAL_ON 0x05
#define FINGERPRINT_LED_GRADUAL_OFF 0x06
#define FINGERPRINT_LED_RED 0x01
#define FINGERPRINT_LED_BLUE 0x02
#define FINGERPRINT_LED_PURPLE 0x03

#define DEFAULTTIMEOUT 1000

struct FingerprintPacket {
  fingerprint_packet(uint8_t type, uint16_t length, uint8_t *data) {
    this->start_code = FINGERPRINT_STARTCODE;
    this->type = type;
    this->length = length;
    address[0] = 0xFF;
    address[1] = 0xFF;
    address[2] = 0xFF;
    address[3] = 0xFF;
    if (length < 64)
      memcpy(this->data, data, length);
    else
      memcpy(this->data, data, 64);
  }
  uint16_t start_code;
  uint8_t address[4];
  uint8_t type;
  uint16_t length;
  uint8_t data[64];
};

class FingerprintReaderComponent : public PollingComponent, public uart::UARTDevice {
  public:
  void update() override;
  void setup() override;
  void dump_config() override;
  boolean verifyPassword();

  void set_fingerprint_count_sensor(sensor::Sensor *fingerprint_count_sensor) { fingerprint_count_sensor_ = fingerprint_count_sensor; }
  void set_status_sensor(sensor::Sensor *status_sensor) { status_sensor_ = status_sensor; }
  void set_capacity_sensor(sensor::Sensor *capacity_sensor) { capacity_sensor_ = capacity_sensor; }
  void set_security_level_sensor(sensor::Sensor *security_level_sensor) { security_level_sensor_ = security_level_sensor; }
  void set_last_finger_id_sensor(sensor::Sensor *last_finger_id_sensor) { last_finger_id_sensor_ = last_finger_id_sensor; }
  void set_last_confidence_sensor(sensor::Sensor *last_confidence_sensor) { last_confidence_sensor_ = last_confidence_sensor; }
  void set_enrolling_binary_sensor(binary_sensor::BinarySensor *enrolling_binary_sensor) { enrolling_binary_sensor_ = enrolling_binary_sensor; }
  void set_sensing_pin(uint8_t pin) { sensing_pin_ = pin }
  void set_password(uint32_t password) { password_ = password }
  void add_on_finger_scanned_callback(std::function<void(bool, int, int, int)> callback) {
    this->finger_scanned_callback_.add(std::move(callback));
  }
  void add_on_enrollment_scan_callback(std::function<void(int, int)> callback) {
    this->enrollment_scan_callback_.add(std::move(callback));
  }
  void add_on_enrollment_callback(std::function<void(bool, int, int)> callback) {
    this->enrollment_callback_.add(std::move(callback));
  }

  void enroll_fingerprint(uint16_t finger_id, int num_buffers) {
    ESP_LOGD(TAG, "Starting enrollment in slot %d", finger_id);
    enrollment_slot_ = finger_id, enrollment_buffers_ = num_buffers, enrollment_image_ = 1;
    enrolling_binary_sensor_->publish_state(true);
  }

  protected:

  void finish_enrollment(int result);
  void scan_and_match();
  int scan_image(int buffer);
  void writeStructuredPacket(const FingerprintPacket &p);
  uint8_t getStructuredPacket(FingerprintPacket *p, uint16_t timeout = DEFAULTTIMEOUT);

  void get_fingerprint_count() {
    finger_->getTemplateCount();
    fingerprint_count_sensor_->publish_state(finger.templateCount);
  }

  uint16_t finger_id_;
  uint16_t confidence_;
  uint16_t template_count_;
  uint16_t status_reg_ = 0x0;
  uint16_t system_id_ = 0x0;
  uint16_t capacity_ = 64;
  uint16_t security_level_ = 0;
  uint32_t device_addr_ = 0xFFFFFFFF;
  uint16_t packet_len_ = 64;
  uint16_t baud_rate_ = 57600;
  uint32_t password_ = 0x0;
  uint8_t sensing_pin_;
  uint8_t enrollment_image_ = 0;
  uint16_t enrollment_slot_ = 0;
  uint8_t enrollment_buffers_ = 5;
  uint16_t templateCount_;
  bool waitingRemoval_ = false;
  Sensor *fingerprint_count_sensor_;
  Sensor *status_sensor_;
  Sensor *capacity_sensor_;
  Sensor *security_level_sensor_;
  Sensor *last_finger_id_sensor_;
  Sensor *last_confidence_sensor_;
  BinarySensor *enrolling_binary_sensor_;
  CallbackManager<void(bool, int, int, int)> finger_scanned_callback_;
  CallbackManager<void(bool, int)> enrollment_scan_callback_;
  CallbackManager<void(bool, int, int)> enrollment_callback_;
};

class FingerScannedTrigger : public Trigger<bool, int, int, int> {
 public:
  explicit FingerScannedTrigger(FingerprintReaderComponent *parent) {
    parent->add_on_finger_scanned_callback(
        [this](bool success, int result, uint16_t finger_id, int confidence) {
          this->trigger(success, result, finger_id, confidence);
        });
  }
};

class EnrollmentScanTrigger : public Trigger<int, int> {
 public:
  explicit EnrollmentScanTrigger(FingerprintReaderComponent *parent) {
    parent->add_on_enrollment_scan_callback(
        [this](int scan_number, uint16_t finger_id) {
          this->trigger(scan_number, finger_id);
        });
  }
};

class EnrollmentTrigger : public Trigger<bool, int, int> {
 public:
  explicit EnrollmentTrigger(FingerprintReaderComponent *parent) {
    parent->add_on_enrollment_callback(
        [this](bool success, int result, uint16_t finger_id) {
          this->trigger(success, result, finger_id);
        });
  }
};

template<typename... Ts> class FingerprintEnrollAction : public Action<Ts...> {
 public:
  FingerprintEnrollAction(FingerprintReaderComponent *parent) : parent_(parent) {}
  TEMPLATABLE_VALUE(uint16_t, finger_id)
  TEMPLATABLE_VALUE(int, num_scans)

  void play(Ts... x) {
    auto finger_id = this->finger_id.value(x...);
    auto num_scans = this->num_scans.value(x...);
    this->parent_->enroll_fingerprint(finger_id, num_scans);
  }

 protected:
  FingerprintReaderComponent *parent_;
};

}  // namespace fingerprint_reader
}  // namespace esphome