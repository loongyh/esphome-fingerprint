#pragma once

#include "esphome/core/component.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/uart/uart.h"

namespace esphome {
namespace fingerprint_reader {

static const uint16_t START_CODE = 0xEF01;
static const uint16_t DEFAULT_TIMEOUT = 1000;

enum class PacketType : uint8_t {
  COMMAND = 0x01,
  DATA = 0x02,
  ACK = 0x07,
  END_DATA = 0x08,
};

enum class Command : uint8_t {
  GET_IMAGE = 0x01,
  IMAGE_2_TZ = 0x02,
  SEARCH = 0x04,
  REG_MODEL = 0x05,
  STORE = 0x06,
  LOAD = 0x07,
  UPLOAD = 0x08,
  DELETE = 0x0C,
  EMPTY = 0x0D,
  READ_SYS_PARAM = 0x0F,
  SET_PASSWORD = 0x12,
  VERIFY_PASSWORD = 0x13,
  HI_SPEED_SEARCH = 0x1B,
  TEMPLATE_COUNT = 0x1D,
};

enum class Response : uint8_t {
  OK = 0x00,
  PACKET_RCV_ERR = 0x01,
  NO_FINGER = 0x02,
  IMAGE_FAIL = 0x03,
  IMAGE_MESS = 0x06,
  FEATURE_FAIL = 0x07,
  NO_MATCH = 0x08,
  NOT_FOUND = 0x09,
  ENROLL_MISMATCH = 0x0A,
  BAD_LOCATION = 0x0B,
  DB_RANGE_FAIL = 0x0C,
  UPLOAD_FEATURE_FAIL = 0x0D,
  PACKET_RESPONSE_FAIL = 0x0E,
  UPLOAD_FAIL = 0x0F,
  DELETE_FAIL = 0x10,
  DB_CLEAR_FAIL = 0x11,
  PASSWORD_FAIL = 0x13,
  INVALID_IMAGE = 0x15,
  FLASH_ERR = 0x18,
  INVALID_REG = 0x1A,
  BAD_PACKET = 0xFE,
  TIMEOUT = 0xFF,
};

enum class LED : uint8_t {
  AURA_CONFIG = 0x35,
  TURN_ON = 0x50,
  TURN_OFF = 0x51,
  BREATHING = 0x01,
  FLASHING = 0x02,
  ALWAYS_ON = 0x03,
  ALWAYS_OFF = 0x04,
  GRADUAL_ON = 0x05,
  GRADUAL_OFF = 0x06,
  RED = 0x01,
  BLUE = 0x02,
  PURPLE = 0x03,
};

struct FingerprintPacket {
  uint16_t start_code;
  uint8_t address[4];
  uint8_t type;
  uint16_t length;
  uint8_t data[64];

  FingerprintPacket(uint8_t *address, uint8_t type, uint16_t length, uint8_t *data) {
    this->start_code = START_CODE;
    memcpy(this->address, address, 4);
    this->type = type;
    this->length = length;
    if (length < 64)
      memcpy(this->data, data, length);
    else
      memcpy(this->data, data, 64);
  }
};

class FingerprintReaderComponent : public PollingComponent, public uart::UARTDevice {
  public:
  void update() override;
  void setup() override;
  void dump_config() override;

  void set_fingerprint_count_sensor(sensor::Sensor *fingerprint_count_sensor) { this->fingerprint_count_sensor_ = fingerprint_count_sensor; }
  void set_status_sensor(sensor::Sensor *status_sensor) { this->status_sensor_ = status_sensor; }
  void set_capacity_sensor(sensor::Sensor *capacity_sensor) { this->capacity_sensor_ = capacity_sensor; }
  void set_security_level_sensor(sensor::Sensor *security_level_sensor) { this->security_level_sensor_ = security_level_sensor; }
  void set_last_finger_id_sensor(sensor::Sensor *last_finger_id_sensor) { this->last_finger_id_sensor_ = last_finger_id_sensor; }
  void set_last_confidence_sensor(sensor::Sensor *last_confidence_sensor) { this->last_confidence_sensor_ = last_confidence_sensor; }
  void set_enrolling_binary_sensor(binary_sensor::BinarySensor *enrolling_binary_sensor) { this->enrolling_binary_sensor_ = enrolling_binary_sensor; }
  void set_password(uint32_t password) { this->password_ = password }
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
    this->enrollment_slot_ = finger_id, this->enrollment_buffers_ = num_buffers, this->enrollment_image_ = 1;
    this->enrolling_binary_sensor_->publish_state(true);
  }

  protected:

  boolean verify_password();
  uint8_t get_parameters(void);
  uint8_t get_image(void);
  uint8_t image_2_tz(uint8_t slot = 1);
  uint8_t create_model(void);
  uint8_t store_model(uint16_t id);
  uint8_t load_model(uint16_t id);
  uint8_t get_model(void);
  uint8_t delete_model(uint16_t id);
  uint8_t empty_database(void);
  uint8_t finger_fast_search(void);
  uint8_t finger_search(uint8_t slot = 1);
  uint8_t get_template_count(void);
  void finish_enrollment(int result);
  void scan_and_match();
  int scan_image(int buffer);
  void writeStructuredPacket(const FingerprintPacket &p);
  uint8_t getStructuredPacket(FingerprintPacket *p, uint16_t timeout = DEFAULTTIMEOUT);

  void get_fingerprint_count() {
    get_template_count();
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
  uint8_t enrollment_image_ = 0;
  uint16_t enrollment_slot_ = 0;
  uint8_t enrollment_buffers_ = 5;
  uint16_t template_count_;
  bool waiting_removal_ = false;
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