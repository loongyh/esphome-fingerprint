#include "fingerprint_reader.h"
#include "esphome/core/log.h"
#include <string.h>

namespace esphome {
namespace fingerprint_reader {

// Based on Adafruit's library: https://github.com/adafruit/Adafruit-Fingerprint-Sensor-Library

#define GET_CMD_PACKET(...)                                              \
uint8_t data[] = {__VA_ARGS__};                                          \
FingerprintPacket packet( ,FINGERPRINT_COMMANDPACKET, sizeof(data), data); \
writeStructuredPacket(packet);                                           \
if (getStructuredPacket(&packet) != FINGERPRINT_OK)                      \
  return FINGERPRINT_PACKETRECIEVEERR;                                   \
if (packet.type != FINGERPRINT_ACKPACKET)                                \
  return FINGERPRINT_PACKETRECIEVEERR;

#define SEND_CMD_PACKET(...)                                             \
  GET_CMD_PACKET(__VA_ARGS__);                                           \
  return packet.data[0];

static const char* TAG = "fingerprint";

void FingerprintReaderComponent::update() {
  if (this->waiting_removal_) {
    if (FINGERPRINT_NOFINGER == this->get_image()) {
      this->waiting_removal_ = false;
    }
    return;
  }

  if (this->enrollment_image_ > this->enrollment_buffers_) {
    ESP_LOGI(TAG, "Creating model");
    int result = this->create_model();
    if (FINGERPRINT_OK == result) {
      ESP_LOGI(TAG, "Storing model");
      result = this->store_model(this->enrollment_slot_);
      if (FINGERPRINT_OK == result) {
        ESP_LOGI(TAG, "Stored model");
      } else {
        ESP_LOGE(TAG, "Error storing model: %d", result);
      }
    } else {
      ESP_LOGE(TAG, "Error creating model: %d", result);
    }
    this->finish_enrollment(result);
    return;
  }

  if (0 == this->enrollment_image_) {
    this->scan_and_match();
    return;

  int result = this->scan_image(this->enrollment_image_);
  if (FINGERPRINT_NOFINGER == result) {
    return;
  }
  this->waiting_removal_ = true;
  if (result != FINGERPRINT_OK) {
    this->finish_enrollment(result);
    return;
  }
  this->enrollment_scan_callback_.call(this->enrollment_image_, this->finger_id_)
  ++this->enrollment_image_;
}

void FingerprintReaderComponent::setup() {
  if (!this->verify_password()) {
    ESP_LOGE(TAG, "Could not find fingerprint sensor");
  }
  this->getParameters();
  this->status_sensor_->publish_state(this->status_reg_);
  this->capacity_sensor_->publish_state(this->capacity_);
  this->security_level_sensor_->publish_state(this->security_level_);
  this->enrolling_binary_sensor_->publish_state(false);
  this->get_fingerprint_count();
}

boolean FingerprintReaderComponent::verify_password() {
  GET_CMD_PACKET(FINGERPRINT_VERIFYPASSWORD, (uint8_t)(this->password_ >> 24),
                (uint8_t)(this->password_ >> 16), (uint8_t)(this->password_ >> 8),
                (uint8_t)(this->password_ & 0xFF));
  if (packet.data[0] == FINGERPRINT_OK)
    return true
  else
    return false
}

uint8_t FingerprintReaderComponent::setPassword(uint32_t password) {
  SEND_CMD_PACKET(FINGERPRINT_SETPASSWORD, (password >> 24), (password >> 16),
                  (password >> 8), password);
}

uint8_t FingerprintReaderComponent::getParameters() {
  GET_CMD_PACKET(FINGERPRINT_READSYSPARAM);

  this->status_reg_ = ((uint16_t)packet.data[1] << 8) | packet.data[2];
  this->system_id_ = ((uint16_t)packet.data[3] << 8) | packet.data[4];
  this->capacity_ = ((uint16_t)packet.data[5] << 8) | packet.data[6];
  this->security_level_ = ((uint16_t)packet.data[7] << 8) | packet.data[8];
  this->device_addr_ = ((uint32_t)packet.data[9] << 24) |
                        ((uint32_t)packet.data[10] << 16) |
                        ((uint32_t)packet.data[11] << 8) |
                        (uint32_t)packet.data[12];
  this->packet_len_ = ((uint16_t)packet.data[13] << 8) | packet.data[14];
  if (this->packet_len_ == 0) {
    this->packet_len_ = 32;
  } else if (this->packet_len_ == 1) {
    this->packet_len_ = 64;
  } else if (this->packet_len_ == 2) {
    this->packet_len_ = 128;
  } else if (this->packet_len_ == 3) {
    this->packet_len_ = 256;
  }
  this->baud_rate_ = (((uint16_t)packet.data[15] << 8) | packet.data[16]) * 9600;

  return packet.data[0];
}

uint8_t FingerprintReaderComponent::get_image(void) {
  SEND_CMD_PACKET(FINGERPRINT_GETIMAGE);
}

uint8_t FingerprintReaderComponent::image_2_tz(uint8_t slot) {
  SEND_CMD_PACKET(FINGERPRINT_IMAGE2TZ, slot);
}

uint8_t FingerprintReaderComponent::create_model(void) {
  SEND_CMD_PACKET(FINGERPRINT_REGMODEL);
}

uint8_t FingerprintReaderComponent::store_model(uint16_t location) {
  SEND_CMD_PACKET(FINGERPRINT_STORE, 0x01, (uint8_t)(location >> 8),
                  (uint8_t)(location & 0xFF));
}

uint8_t FingerprintReaderComponent::load_model(uint16_t location) {
  SEND_CMD_PACKET(FINGERPRINT_LOAD, 0x01, (uint8_t)(location >> 8),
                  (uint8_t)(location & 0xFF));
}

uint8_t FingerprintReaderComponent::get_model(void) {
  SEND_CMD_PACKET(FINGERPRINT_UPLOAD, 0x01);
}

uint8_t FingerprintReaderComponent::delete_model(uint16_t location) {
  SEND_CMD_PACKET(FINGERPRINT_DELETE, (uint8_t)(location >> 8),
                  (uint8_t)(location & 0xFF), 0x00, 0x01);
}

uint8_t FingerprintReaderComponent::empty_database(void) {
  SEND_CMD_PACKET(FINGERPRINT_EMPTY);
}

uint8_t FingerprintReaderComponent::finger_fast_search(void) {
  // high speed search of slot #1 starting at page 0x0000 and page #0x00A3
  GET_CMD_PACKET(FINGERPRINT_HISPEEDSEARCH, 0x01, 0x00, 0x00, 0x00, 0xA3);
  this->finger_id_ = 0xFFFF;
  this->confidence_ = 0xFFFF;

  this->finger_id_ = packet.data[1];
  this->finger_id_ <<= 8;
  this->finger_id_ |= packet.data[2];

  this->confidence_ = packet.data[3];
  this->confidence_ <<= 8;
  this->confidence_ |= packet.data[4];

  return packet.data[0];
}

uint8_t FingerprintReaderComponent::finger_search(uint8_t slot) {
  // search of slot starting thru the capacity
  GET_CMD_PACKET(FINGERPRINT_SEARCH, slot, 0x00, 0x00, this->capacity_ >> 8,
                 this->capacity_ & 0xFF);

  this->finger_id_ = 0xFFFF;
  this->confidence_ = 0xFFFF;

  this->finger_id_ = packet.data[1];
  this->finger_id_ <<= 8;
  this->finger_id_ |= packet.data[2];

  this->confidence_ = packet.data[3];
  this->confidence_ <<= 8;
  this->confidence_ |= packet.data[4];

  return packet.data[0];
}

uint8_t FingerprintReaderComponent::led_control(bool on) {
  if (on) {
    SEND_CMD_PACKET(FINGERPRINT_LEDON);
  } else {
    SEND_CMD_PACKET(FINGERPRINT_LEDOFF);
  }
}

uint8_t FingerprintReaderComponent::led_control(uint8_t control, uint8_t speed,
                                         uint8_t coloridx, uint8_t count) {
  SEND_CMD_PACKET(FINGERPRINT_AURALEDCONFIG, control, speed, coloridx, count);
}

uint8_t FingerprintReaderComponent::get_template_count(void) {
  GET_CMD_PACKET(FINGERPRINT_TEMPLATECOUNT);

  this->template_count_ = packet.data[1];
  this->template_count_ <<= 8;
  this->template_count_ |= packet.data[2];

  return packet.data[0];
}

void FingerprintReaderComponent::finish_enrollment(int result) {
  this->enrollment_callback_.call(FINGERPRINT_OK == result, result, this->enrollment_slot_)
  this->enrollment_image_ = 0;
  this->enrollment_slot_ = 0;
  this->enrolling_binary_sensor_->publish_state(false);
}

void FingerprintReaderComponent::scan_and_match() {
  int result = scan_image(1);
  int finger_id = -1;
  int confidence = 0;
  if (FINGERPRINT_NOFINGER == result) {
    return;
  }
  if (FINGERPRINT_OK == result) {
    result = this->fingerSearch();
    if (FINGERPRINT_OK == result) {
      finger_id = this->finger_id_;
      last_finger_id_sensor_->publish_state(finger_id);
      confidence = this->confidence_;
      last_confidence_sensor_->publish_state(confidence);
    }
  }
  this->waiting_removal_ = true;
  this->finger_scanned_callback_.call(FINGERPRINT_OK == result, result, finger_id, confidence)
}

int FingerprintReaderComponent::scan_image(int buffer) {
  ESP_LOGD(TAG, "Getting image %d", buffer);
  int p = this->getImage();
  if (p != FINGERPRINT_OK) {
    ESP_LOGD(TAG, "No image. Result: %d", p);
    return p;
  }

  ESP_LOGD(TAG, "Processing image %d", buffer);
  p = this->image2Tz(buffer);
  switch (p) {
    case FINGERPRINT_OK:
      ESP_LOGI(TAG, "Processed image %d", buffer);
      return p;
    case FINGERPRINT_IMAGEMESS:
      ESP_LOGE(TAG, "Image too messy");
      return p;
    case FINGERPRINT_PACKETRECIEVEERR:
      ESP_LOGE(TAG, "Communication error");
      return p;
    case FINGERPRINT_FEATUREFAIL:
    case FINGERPRINT_INVALIDIMAGE:
      ESP_LOGE(TAG, "Could not find fingerprint features");
      return p;
    default:
      ESP_LOGE(TAG, "Unknown error");
      return p;
  }
}

void FingerprintReaderComponent::writeStructuredPacket(const FingerprintPacket &packet) {

  this->write_byte((uint8_t)(packet.start_code >> 8));
  this->write_byte((uint8_t)(packet.start_code & 0xFF));
  this->write_byte(packet.address[0]);
  this->write_byte(packet.address[1]);
  this->write_byte(packet.address[2]);
  this->write_byte(packet.address[3]);
  this->write_byte(packet.type);

  uint16_t wire_length = packet.length + 2;
  this->write_byte((uint8_t)(wire_length >> 8));
  this->write_byte((uint8_t)(wire_length & 0xFF));

  uint16_t sum = ((wire_length) >> 8) + ((wire_length)&0xFF) + packet.type;
  for (uint8_t i = 0; i < packet.length; i++) {
    this->write_byte(packet.data[i]);
    sum += packet.data[i];
  }

  this->write_byte((uint8_t)(sum >> 8));
  this->write_byte((uint8_t)(sum & 0xFF));

  return;
}

uint8_t FingerprintReaderComponent::getStructuredPacket(FingerprintPacket *packet, uint16_t timeout) {
  uint8_t byte;
  uint16_t idx = 0, timer = 0;

  while (true) {
    while (!this->available()) {
      delay(1);
      timer++;
      if (timer >= timeout) {
        return FINGERPRINT_TIMEOUT;
      }
    }
    byte = this->read();
    switch (idx) {
    case 0:
      if (byte != (START_CODE >> 8))
        continue;
      packet->start_code = (uint16_t)byte << 8;
      break;
    case 1:
      packet->start_code |= byte;
      if (packet->start_code != START_CODE)
        return FINGERPRINT_BADPACKET;
      break;
    case 2:
    case 3:
    case 4:
    case 5:
      packet->address[idx - 2] = byte;
      break;
    case 6:
      packet->type = byte;
      break;
    case 7:
      packet->length = (uint16_t)byte << 8;
      break;
    case 8:
      packet->length |= byte;
      break;
    default:
      packet->data[idx - 9] = byte;
      if ((idx - 8) == packet->length) {
        return FINGERPRINT_OK;
      }
      break;
    }
    idx++;
  }
  // Shouldn't get here so...
  return FINGERPRINT_BADPACKET;
}

void FingerprintReaderComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "FINGERPRINT_READER:");
  // ESP_LOGCONFIG(TAG, "  RSSI: %d dB", this->rssi_);
}

}  // namespace fingerprint_reader
}  // namespace esphome