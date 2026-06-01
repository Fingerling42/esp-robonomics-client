#include <Arduino.h>
#include <Call.h>
#include <Robonomics.h>
#include <cstring>

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

void setup() {
  Serial.begin(115200);

  delay(3000);

  Serial.println("Starting set_devices example");

  robonomics.generateAndSetPrivateKey();

  const RobonomicsPublicKey device = getPublicKeyFromAddr(robonomics.getSs58Address());
  runSs58DecodingTests(robonomics.getSs58Address());
  runSetDevicesEncodingTests(device);
  runSetDevicesApiValidationTests(robonomics.getSs58Address());
}

void loop() {
  delay(2000);
  Serial.println("Alive");
}
