#include <Arduino.h>
#include <Call.h>
#include <Robonomics.h>
#include <cstring>

#ifndef RUN_LIVE_SET_DEVICES_TEST
#define RUN_LIVE_SET_DEVICES_TEST 0
#endif

#if RUN_LIVE_SET_DEVICES_TEST
#include <WiFi.h>
#include "secrets.h"
#endif

Robonomics robonomics;

void checkResult(const char* name, bool passed) {
  Serial.printf("[%s] %s\r\n", passed ? "PASS" : "FAIL", name);
}

void printHex(const Data& data) {
  for (const auto byte : data) {
    Serial.printf("%02x", byte);
  }
  Serial.println();
}

void checkCallSize(const char* name, const Data& call, size_t expectedSize) {
  const bool passed = call.size() == expectedSize;
  Serial.printf(
    "[%s] %s: size=%u expected=%u\r\n",
    passed ? "PASS" : "FAIL",
    name,
    static_cast<unsigned int>(call.size()),
    static_cast<unsigned int>(expectedSize)
  );
}

void checkByte(const char* name, const Data& data, size_t index, uint8_t expected) {
  const bool passed = index < data.size() && data[index] == expected;
  Serial.printf(
    "[%s] %s: byte[%u]=0x%02x expected=0x%02x\r\n",
    passed ? "PASS" : "FAIL",
    name,
    static_cast<unsigned int>(index),
    index < data.size() ? data[index] : 0,
    expected
  );
}

void checkAccountId(const Data& call, const RobonomicsPublicKey& device) {
  constexpr size_t accountIdOffset = 3;
  bool passed = call.size() >= accountIdOffset + PUBLIC_KEY_LENGTH;
  for (size_t i = 0; passed && i < PUBLIC_KEY_LENGTH; ++i) {
    passed = call[accountIdOffset + i] == device.bytes[i];
  }
  Serial.printf("[%s] one device AccountId32 bytes\r\n", passed ? "PASS" : "FAIL");
}

void runSetDevicesEncodingTests(const RobonomicsPublicKey& device) {
  const Data head = {0x37, 0x02};

  const Data emptyCall = callRwsSetDevices(head, {});
  checkCallSize("empty devices", emptyCall, 3);
  checkByte("empty devices compact length", emptyCall, 2, 0x00);

  const Data oneDeviceCall = callRwsSetDevices(head, {device});
  checkCallSize("one device", oneDeviceCall, 35);
  checkByte("one device compact length", oneDeviceCall, 2, 0x04);
  checkAccountId(oneDeviceCall, device);
  Serial.print("one device call hex: ");
  printHex(oneDeviceCall);

  const Data twoDevicesCall = callRwsSetDevices(head, {device, device});
  checkCallSize("two devices", twoDevicesCall, 67);
  checkByte("two devices compact length", twoDevicesCall, 2, 0x08);

  const std::vector<RobonomicsPublicKey> maxDevices(32, device);
  const Data maxDevicesCall = callRwsSetDevices(head, maxDevices);
  checkCallSize("32 devices", maxDevicesCall, 1027);
  checkByte("32 devices compact length", maxDevicesCall, 2, 0x80);

  const std::vector<RobonomicsPublicKey> tooManyDevices(33, device);
  const Data tooManyDevicesCall = callRwsSetDevices(head, tooManyDevices);
  checkCallSize("33 devices rejected", tooManyDevicesCall, 0);
}

void runSs58DecodingTests(const char* address) {
  RobonomicsPublicKey publicKey;
  checkResult("valid SS58 address", getPublicKeyFromAddr(address, publicKey));

  char invalidBase58Address[ADDRESS_LENGTH + 1];
  strncpy(invalidBase58Address, address, sizeof(invalidBase58Address));
  invalidBase58Address[ADDRESS_LENGTH] = '\0';
  invalidBase58Address[ADDRESS_LENGTH - 1] = '0';
  checkResult("invalid Base58 symbol rejected", !getPublicKeyFromAddr(invalidBase58Address, publicKey));

  char invalidChecksumAddress[ADDRESS_LENGTH + 1];
  strncpy(invalidChecksumAddress, address, sizeof(invalidChecksumAddress));
  invalidChecksumAddress[ADDRESS_LENGTH] = '\0';
  invalidChecksumAddress[ADDRESS_LENGTH - 1] =
    invalidChecksumAddress[ADDRESS_LENGTH - 1] == '1' ? '2' : '1';
  checkResult("invalid SS58 checksum rejected", !getPublicKeyFromAddr(invalidChecksumAddress, publicKey));
}

void runSetDevicesApiValidationTests(const char* address) {
  const std::vector<std::string> tooManyDevices(33, address);
  const char* tooManyResult = robonomics.sendRWSSetDevices(tooManyDevices);
  checkResult(
    "API rejects 33 devices locally",
    strcmp(tooManyResult, "error") == 0 &&
      !robonomics.lastExtrinsicOk() &&
      strcmp(robonomics.lastExtrinsicErrorMessage(), "Too many RWS devices: maximum is 32") == 0
  );

  std::string invalidAddress = address;
  invalidAddress[ADDRESS_LENGTH - 1] = '0';
  const char* invalidAddressResult = robonomics.sendRWSSetDevices({invalidAddress});
  checkResult(
    "API rejects invalid SS58 locally",
    strcmp(invalidAddressResult, "error") == 0 &&
      !robonomics.lastExtrinsicOk() &&
      strcmp(robonomics.lastExtrinsicErrorMessage(), "Invalid SS58 device address at index 0") == 0
  );
}

#if RUN_LIVE_SET_DEVICES_TEST
bool connectWifi() {
  constexpr unsigned long wifiTimeoutMs = 30000;
  const unsigned long startedAt = millis();

  Serial.printf("Connecting to Wi-Fi SSID: %s\r\n", LIVE_WIFI_SSID);
  WiFi.begin(LIVE_WIFI_SSID, LIVE_WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED && millis() - startedAt < wifiTimeoutMs) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[FAIL] Wi-Fi connection timeout");
    return false;
  }

  Serial.printf("[PASS] Wi-Fi connected, IP: %s\r\n", WiFi.localIP().toString().c_str());
  return true;
}

void runLiveSetDevicesTest(const std::string& deviceAddress) {
  Serial.println("Starting LIVE rws.set_devices test");
  if (!connectWifi()) {
    return;
  }

  robonomics.setPrivateKey(LIVE_OWNER_PRIVATE_KEY_HEX);
  robonomics.setup(LIVE_ROBONOMICS_RPC_HOST);

  Serial.printf("Owner address: %s\r\n", robonomics.getSs58Address());
  Serial.printf("Device address: %s\r\n", deviceAddress.c_str());
  Serial.println("Submitting rws.set_devices transaction...");

  const char* result = robonomics.sendRWSSetDevices({deviceAddress});
  Serial.printf("Extrinsic result: %s\r\n", result);
  Serial.printf("Extrinsic accepted by RPC: %s\r\n", robonomics.lastExtrinsicOk() ? "yes" : "no");
  if (!robonomics.lastExtrinsicOk()) {
    Serial.printf("Extrinsic error: %s\r\n", robonomics.lastExtrinsicErrorMessage());
  }
}
#endif

void setup() {
  Serial.begin(115200);

  delay(3000);

  Serial.println("Starting set_devices example");

  robonomics.generateAndSetPrivateKey();
  const std::string deviceAddress = robonomics.getSs58Address();

  const RobonomicsPublicKey device = getPublicKeyFromAddr(deviceAddress.c_str());
  runSs58DecodingTests(deviceAddress.c_str());
  runSetDevicesEncodingTests(device);
  runSetDevicesApiValidationTests(deviceAddress.c_str());

#if RUN_LIVE_SET_DEVICES_TEST
  runLiveSetDevicesTest(deviceAddress);
#else
  Serial.println("LIVE rws.set_devices test is disabled");
#endif
}

void loop() {
  delay(2000);
  Serial.println("Alive");
}
