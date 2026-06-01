#include "Robonomics.h"
#include <inttypes.h>
#include "address.h"
#include <Arduino.h>
#include <Ed25519.h>
#include "JsonUtils.h"

static const char *TAG = "ROBONOMICS";

void Robonomics::setup(String host) {
    blockchainUtils.setup(host);
}

void Robonomics::disconnectWebsocket() {
    blockchainUtils.disconnect();
}

void Robonomics::generateAndSetPrivateKey() {
    uint8_t robonomicsPrivateKey[32];
    Ed25519::generatePrivateKey(robonomicsPrivateKey);
    setPrivateKey(robonomicsPrivateKey);
}

void Robonomics::setPrivateKey(const char* hexPrivateKey) {
    uint8_t privateKey[KEYS_SIZE];
    hex2bytes(hexPrivateKey, privateKey);
    setPrivateKey(privateKey);
}

void Robonomics::setPrivateKey(uint8_t *privateKey) {
    memcpy(privateKey_, privateKey, KEYS_SIZE);
    Ed25519::derivePublicKey(publicKey_, privateKey_);
    char* tempAddress = getAddrFromPrivateKey(privateKey_, ROBONOMICS_PREFIX);
    if (tempAddress != nullptr) {
        strncpy(ss58Address, tempAddress, SS58_ADDRESS_SIZE); // Leave space for null terminator
        ss58Address[SS58_ADDRESS_SIZE] = '\0'; // Ensure null termination
        delete[] tempAddress;
        Serial.printf("Robonomics Address: %s\r\n", ss58Address);
    } else {
        Serial.println("Failed to get address from public key.");
    }
}

const char* Robonomics::getPrivateKey() const {
    static char hexString[KEYS_SIZE * 2 + 1];
    size_t length = sizeof(privateKey_) / sizeof(privateKey_[0]);
    bytes2hex(privateKey_, length, hexString);
    return hexString;
}

const char* Robonomics::getSs58Address() const {
    return ss58Address;
}

const char* Robonomics::sendCustomCall() {
    Data call = createCall();

    const char* res = createAndSendExtrinsic(call);
    return res;
}

const char* Robonomics::sendDatalogRecord(const std::string& data) {
    Data head_dr_  = Data{0x33,0};
    Data call = callDatalogRecord(head_dr_, data);

    const char* res = createAndSendExtrinsic(call);
    return res;
}

const char* Robonomics::sendRWSDatalogRecord(const std::string& data, const char *owner_address) {
    Data head_dr_ = Data{0x33,0};
    Data head_rws_ = Data{0x37,0};
    Data call_nested = callDatalogRecord(head_dr_, data);
    RobonomicsPublicKey ownerKey = getPublicKeyFromAddr(owner_address);
    Data call = callRws(head_rws_, ownerKey, call_nested);

    const char* res = createAndSendExtrinsic(call);
    return res;
}

const char* Robonomics::sendRWSSetDevices(const std::vector<std::string>& deviceAddresses) {
    constexpr size_t maxDevicesAmount = 32;
    if (deviceAddresses.size() > maxDevicesAmount) {
        return setLocalExtrinsicError("Too many RWS devices: maximum is 32");
    }

    std::vector<RobonomicsPublicKey> deviceKeys;
    deviceKeys.reserve(deviceAddresses.size());
    for (size_t i = 0; i < deviceAddresses.size(); ++i) {
        RobonomicsPublicKey deviceKey;
        if (!getPublicKeyFromAddr(deviceAddresses[i].c_str(), deviceKey)) {
            return setLocalExtrinsicError(String("Invalid SS58 device address at index ") + String(i));
        }
        deviceKeys.push_back(deviceKey);
    }

    Data head_rws_set_devices_ = Data{0x37, 0x02};
    Data call = callRwsSetDevices(head_rws_set_devices_, deviceKeys);
    if (call.empty()) {
        return setLocalExtrinsicError("Failed to encode RWS set_devices call");
    }

    return createAndSendExtrinsic(call);
}

#ifdef ROBONOMICS_USE_WS
const char* Robonomics::sendRWSDatalogRecordAndWatch(const std::string& data, const char *owner_address, uint32_t timeout_ms) {
    Data head_dr_ = Data{0x33,0};
    Data head_rws_ = Data{0x37,0};
    Data call_nested = callDatalogRecord(head_dr_, data);
    RobonomicsPublicKey ownerKey = getPublicKeyFromAddr(owner_address);
    Data call = callRws(head_rws_, ownerKey, call_nested);

    // Reuse the same extrinsic construction steps, but submit with watch.
    const char* error_res = "error";
    uint64_t payloadNonce;
    if (!getNonce(& blockchainUtils, ss58Address, &payloadNonce)) return error_res;
    std::string payloadBlockHash;
    if (!getGenesisBlockHash(& blockchainUtils, &payloadBlockHash)) return error_res;
    payloadBlockHash.erase(0, 2);
    uint32_t payloadEra = getEra();
    uint64_t payloadTip = getTip();
    uint32_t payloadSpecVersion;
    uint32_t payloadTransactionVersion;
    if (!extractRuntimeVersions(& blockchainUtils, & payloadSpecVersion, & payloadTransactionVersion)) return error_res;

    Data data_ = createPayload(call, payloadEra, payloadNonce, payloadTip, payloadSpecVersion, payloadTransactionVersion, payloadBlockHash, payloadBlockHash);
    Data signature_ = createSignature(data_, privateKey_, publicKey_);
    std::vector<std::uint8_t> pubKey( reinterpret_cast<std::uint8_t*>(std::begin(publicKey_)), reinterpret_cast<std::uint8_t*>(std::end(publicKey_)));
    Data edata_ = createSignedExtrinsic(signature_, pubKey, payloadEra, payloadNonce, payloadTip, call);
    int requestId = blockchainUtils.getRequestId();
    return sendExtrinsicAndWatch(edata_, requestId, timeout_ms);
}
#endif

const char* Robonomics::setLocalExtrinsicError(const String& message) {
    last_extrinsic_ok_ = false;
    last_extrinsic_error_code_ = 0;
    last_extrinsic_error_message_ = message;
    last_extrinsic_result_ = "error";
    return last_extrinsic_result_.c_str();
}

const char* Robonomics::createAndSendExtrinsic(Data call) {
    const char* error_res = "error";

    uint64_t payloadNonce;
    if (!getNonce(& blockchainUtils, ss58Address, &payloadNonce)) {
        last_extrinsic_ok_ = false;
        last_extrinsic_error_code_ = 0;
        last_extrinsic_error_message_ = "Failed to obtain nonce (system_accountNextIndex)";
        last_extrinsic_result_ = error_res;
        return error_res;
    }
    std::string payloadBlockHash;
    if (!getGenesisBlockHash(& blockchainUtils, &payloadBlockHash)) {
        last_extrinsic_ok_ = false;
        last_extrinsic_error_code_ = 0;
        last_extrinsic_error_message_ = "Failed to obtain genesis block hash (chain_getBlockHash(0))";
        last_extrinsic_result_ = error_res;
        return error_res;
    }
    payloadBlockHash.erase(0, 2);
    uint32_t payloadEra = getEra();
    uint64_t payloadTip = getTip();
    uint32_t payloadSpecVersion;
    uint32_t payloadTransactionVersion;
    if (!extractRuntimeVersions(& blockchainUtils, & payloadSpecVersion, & payloadTransactionVersion)) {
        last_extrinsic_ok_ = false;
        last_extrinsic_error_code_ = 0;
        last_extrinsic_error_message_ = "Failed to obtain runtime versions (state_getRuntimeVersion)";
        last_extrinsic_result_ = error_res;
        return error_res;
    }
    // Serial.printf("Spec version: %" PRIu32 ", tx version: %" PRIu32 ", nonce: %llu, era: %" PRIu32 ", tip: %llu\r\n", payloadSpecVersion, payloadTransactionVersion, (unsigned long long)payloadNonce, payloadEra, (unsigned long long)payloadTip);
    Data data_ = createPayload(call, payloadEra, payloadNonce, payloadTip, payloadSpecVersion, payloadTransactionVersion, payloadBlockHash, payloadBlockHash);
    Data signature_ = createSignature(data_, privateKey_, publicKey_);
    std::vector<std::uint8_t> pubKey( reinterpret_cast<std::uint8_t*>(std::begin(publicKey_)), reinterpret_cast<std::uint8_t*>(std::end(publicKey_)));
    Data edata_ = createSignedExtrinsic(signature_, pubKey, payloadEra, payloadNonce, payloadTip, call);
    int requestId = blockchainUtils.getRequestId();
    const char* res = sendExtrinsic(edata_, requestId);
    return res;
}

void Robonomics::signMessage(const String &message, String &signature) {
    std::string msgStr = std::string(message.c_str());
    // std::string msgStr(message.c_str());
    Data msgData(msgStr.begin(), msgStr.end());
    Data sigData = createSignature(msgData, privateKey_, publicKey_);
    for (int k = 0; k < sigData.size(); k++) 
        printf("%02x", sigData[k]);
    printf("\r\n");
    String sigHex = "";
    for (size_t i = 0; i < sigData.size(); i++) {
        if (sigData[i] < 0x10) {
            sigHex += "0"; // pad with a zero if needed
        }
        sigHex += String(sigData[i], HEX);
    }
    signature = sigHex;
}

Data Robonomics::createCall() {
    Data call;
    std::vector<uint8_t> callStr = hex2bytes(CALL_ENCODED);
    append(call, callStr);
    Serial.printf("Call size: %zu\r\n", call.size());
    // for (int k = 0; k < call.size(); k++) 
    //     printf("%02x", call[k]);
    // printf("\r\n");
    return call;
}

Data Robonomics::createPayload(Data call, uint32_t era, uint64_t nonce, uint64_t tip, uint32_t sv, uint32_t tv, std::string gen, std::string block) {
    Data data_ = doPayload (call, era, nonce, tip, sv, tv, gen, block);
    Serial.printf("Payload size: %zu\r\n", data_.size());
    // for (int k = 0; k < data_.size(); k++) 
    //     printf("%02x", data_[k]);
    // printf("\r\n");
    return data_;
}

Data Robonomics::createSignature(Data data, uint8_t privateKey[32], uint8_t publicKey[32]) {
    Data signature_ = doSign (data, privateKey, publicKey);
    Serial.printf("Signature size: %zu\r\n", signature_.size());
    // for (int k = 0; k < signature_.size(); k++) 
    //     printf("%02x", signature_[k]);
    // printf("\r\n");
    return signature_;
}

Data Robonomics::createSignedExtrinsic(Data signature, Data pubKey, uint32_t era, uint64_t nonce, uint64_t tip, Data call) {
    // Signer address is MultiAddress::AccountId(0x00 + 32-byte public key) for modern runtimes.
    Data signerAddress = encodeAccountId(pubKey, /*raw=*/false);
    Data edata_ = doEncode(signature, signerAddress, era, nonce, tip, call);
    Serial.printf("Extrinsic %s: size %zu\r\n", "Datalog", edata_.size());
    // for (int k = 0; k < edata_.size(); k++) 
    //     printf("%02x", edata_[k]);
    // printf("\r\n");
    return edata_;
}

const char* Robonomics::sendExtrinsic(Data extrinsicData, int requestId) {
    String extrinsicMessage = fillParamsJs(extrinsicData, requestId);
    Serial.printf("After to string: %s\r\n", extrinsicMessage.c_str());
    // Serial.print(extrinsicMessage);
    JSONVar result = blockchainUtils.rpcRequest(extrinsicMessage);
    if (result.hasOwnProperty("result")) {
        last_extrinsic_result_ = JSON.stringify(result["result"]);
        last_extrinsic_ok_ = true;
        last_extrinsic_error_code_ = 0;
        last_extrinsic_error_message_ = "";
    } else {
        last_extrinsic_result_ = JSON.stringify(result["error"]);
        last_extrinsic_ok_ = false;
        last_extrinsic_error_code_ = 0;
        last_extrinsic_error_message_ = last_extrinsic_result_;

        // Try to extract standard JSON-RPC error fields if present.
        if (result.hasOwnProperty("error")) {
            JSONVar err = result["error"];
            if (err.hasOwnProperty("code")) {
                last_extrinsic_error_code_ = (long)err["code"];
            }
            if (err.hasOwnProperty("message")) {
                last_extrinsic_error_message_ = (const char*)err["message"];
            }
        }
    }
    Serial.printf("Extrinsic result: %s", last_extrinsic_result_.c_str());
    return last_extrinsic_result_.c_str();
}

#ifdef ROBONOMICS_USE_WS
const char* Robonomics::sendExtrinsicAndWatch(Data extrinsicData, int requestId, uint32_t timeout_ms) {
    String extrinsicMessage = fillParamsWatchJs(extrinsicData, requestId);
    Serial.printf("After to string (watch): %s\r\n", extrinsicMessage.c_str());

    JSONVar watchRes = blockchainUtils.rpcRequestAndWatch(extrinsicMessage, timeout_ms);
    last_watch_result_ = JSON.stringify(watchRes);

    // Fill watch summary fields
    last_watch_ok_ = false;
    last_watch_status_ = "";
    if (watchRes.hasOwnProperty("ok")) {
        last_watch_ok_ = (bool)watchRes["ok"];
    }
    if (watchRes.hasOwnProperty("status")) {
        last_watch_status_ = (const char*)watchRes["status"];
    }

    // Also map watch result into "extrinsic status" for convenience:
    // if watch reached inBlock/finalized -> ok.
    last_extrinsic_ok_ = last_watch_ok_;
    if (!last_watch_ok_) {
        last_extrinsic_error_message_ = last_watch_result_;
    }

    Serial.printf("Extrinsic watch result: %s\r\n", last_watch_result_.c_str());
    return last_watch_result_.c_str();
}
#endif
