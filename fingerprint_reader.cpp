#include "fingerprint_reader.h"
#include "esphome/core/log.h"
#include <string.h>

namespace esphome {
namespace fingerprint_reader {

#define GET_CMD_PACKET(...)                                              \
uint8_t data[] = {__VA_ARGS__};                                          \
FingerprintPacket packet(FINGERPRINT_COMMANDPACKET, sizeof(data), data); \
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
  if (this->waitingRemoval_) {
    if (FINGERPRINT_NOFINGER == this->getImage()) {
      this->waitingRemoval_ = false;
    }
    return;
  }

  if (enrollment_image_ > enrollment_buffers_) {
    ESP_LOGI(TAG, "Creating model");
    int result = this->createModel();
    if (FINGERPRINT_OK == result) {
      ESP_LOGI(TAG, "Storing model");
      result = this->storeModel(enrollment_slot_);
      if (FINGERPRINT_OK == result) {
        ESP_LOGI(TAG, "Stored model");
      } else {
        ESP_LOGE(TAG, "Error storing model: %d", result);
      }
    } else {
      ESP_LOGE(TAG, "Error creating model: %d", result);
    }
    finish_enrollment(result);
    return;
  }

  if (HIGH == digitalRead(sensing_pin_)) {
    ESP_LOGV(TAG, "No touch sensing");
    return;
  }

  if (0 == enrollment_image_) {
    scan_and_match();
    return;

  int result = scan_image(enrollment_image_);
  if (FINGERPRINT_NOFINGER == result) {
    return;
  }
  this->waitingRemoval_ = true;
  if (result != FINGERPRINT_OK) {
    finish_enrollment(result);
    return;
  }
  this->enrollment_scan_callback_.call(enrollment_image_, finger_id)
  ++enrollment_image_;
}

void FingerprintReaderComponent::setup() {
  pinMode(sensing_pin_, INPUT);
  if (!this->verifyPassword()) {
    ESP_LOGE(TAG, "Could not find fingerprint sensor");
  }
  this->getParameters();
  status_sensor_->publish_state(this->status_reg_);
  capacity_sensor_->publish_state(this->capacity_);
  security_level_sensor_->publish_state(this->security_level_);
  enrolling_binary_sensor_->publish_state(false);
  get_fingerprint_count();
}

boolean FingerprintReaderComponent::verifyPassword() {
  GET_CMD_PACKET(FINGERPRINT_VERIFYPASSWORD, (uint8_t)(password_ >> 24),
                (uint8_t)(password_ >> 16), (uint8_t)(password_ >> 8),
                (uint8_t)(password_ & 0xFF));
  if (packet.data[0] == FINGERPRINT_OK)
    return true
  else
    return false
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

void FingerprintReaderComponent::finish_enrollment(int result) {
  this->enrollment_callback_.call(FINGERPRINT_OK == result, result, enrollment_slot_)
  enrollment_image_ = 0;
  enrollment_slot_ = 0;
  enrolling_binary_sensor_->publish_state(false);
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
  this->waitingRemoval_ = true;
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
      if (byte != (FINGERPRINT_STARTCODE >> 8))
        continue;
      packet->start_code = (uint16_t)byte << 8;
      break;
    case 1:
      packet->start_code |= byte;
      if (packet->start_code != FINGERPRINT_STARTCODE)
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