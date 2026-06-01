#pragma once

#include "Call.h"
#include "Extrinsic.h"
#include "BlockchainUtils.h"

#include <Arduino.h>
#include "PayloadParamsUtils.h"

class Robonomics {
private:
    BlockchainUtils blockchainUtils;
    uint8_t publicKey_[KEYS_SIZE];
    uint8_t privateKey_[KEYS_SIZE];
    char ss58Address[SS58_ADDRESS_SIZE + 1];
    bool got_extrinsic_result = false;
    // Keep last extrinsic result alive after returning const char*.
    // NOTE: Previously sendExtrinsic() returned c_str() of a local String (dangling pointer).
    String last_extrinsic_result_;
    bool last_extrinsic_ok_ = false;
    long last_extrinsic_error_code_ = 0;
    String last_extrinsic_error_message_;
    String last_watch_result_;
    bool last_watch_ok_ = false;
    String last_watch_status_;
    const char* setLocalExtrinsicError(const String& message);
    const char* createAndSendExtrinsic(Data call);
    Data createCall();
    Data createPayload(Data call, uint32_t era, uint64_t nonce, uint64_t tip, uint32_t sv, uint32_t tv, std::string gen, std::string block);
    Data createSignature(Data data, uint8_t privateKey[32], uint8_t publicKey[32]);
    Data createSignedExtrinsic(Data signature, Data pubKey, uint32_t era, uint64_t nonce, uint64_t tip, Data call);
    const char* sendExtrinsic(Data extrinsicData, int requestId);
#ifdef ROBONOMICS_USE_WS
    const char* sendExtrinsicAndWatch(Data extrinsicData, int requestId, uint32_t timeout_ms);
#endif
public:
    void setup(String host);
    void disconnectWebsocket();
    void generateAndSetPrivateKey();
    void setPrivateKey(uint8_t *privateKey);
    void setPrivateKey(const char* hexPrivateKey);
    const char* sendDatalogRecord(const std::string& data);
    const char* sendRWSDatalogRecord(const std::string& data, const char *owner_address);
    const char* sendRWSSetDevices(const std::vector<std::string>& deviceAddresses);
    const char* sendCustomCall();
    const char* getSs58Address() const;
    const char* getPrivateKey() const;
    void signMessage(const String &message, String &signature);

    // Extrinsic send status helpers.
    // These reflect the most recent `author_submitExtrinsic` attempt.
    bool lastExtrinsicOk() const { return last_extrinsic_ok_; }
    long lastExtrinsicErrorCode() const { return last_extrinsic_error_code_; }
    const char* lastExtrinsicErrorMessage() const { return last_extrinsic_error_message_.c_str(); }
    const char* lastExtrinsicResult() const { return last_extrinsic_result_.c_str(); }

    // Watch status helpers (only meaningful if `author_submitAndWatchExtrinsic` is used).
    bool lastWatchOk() const { return last_watch_ok_; }
    const char* lastWatchStatus() const { return last_watch_status_.c_str(); }
    const char* lastWatchResult() const { return last_watch_result_.c_str(); }

#ifdef ROBONOMICS_USE_WS
    // Submit extrinsic and wait for inBlock/finalized/terminal failure.
    const char* sendRWSDatalogRecordAndWatch(const std::string& data, const char *owner_address, uint32_t timeout_ms);
#endif
};
