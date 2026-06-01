#include <Arduino.h>
#include "PayloadParamsUtils.h"
#include <string>

JSONVar emptyParamsArray;
JSONVar paramsArray;

/** Genesis block hash is chain-constant; avoid RPC on every datalog send. */
static bool genesis_hash_cached = false;
static std::string cached_genesis_hash;

/** Runtime spec/tx versions change only on chain upgrades (rare). */
static bool runtime_versions_cached = false;
static uint32_t cached_spec_version = 0;
static uint32_t cached_tx_version = 0;
static unsigned long runtime_versions_cached_at_ms = 0;
static const unsigned long RUNTIME_VERSIONS_CACHE_TTL_MS = 60UL * 60UL * 1000UL;

static void invalidateRuntimeVersionCache() {
    runtime_versions_cached = false;
    cached_spec_version = 0;
    cached_tx_version = 0;
    runtime_versions_cached_at_ms = 0;
}

uint32_t getEra() {
    return 0;
}

uint64_t getTip() {
    return 0;
}

bool getGenesisBlockHash(BlockchainUtils *blockchainUtils, std::string *blockHash) {
    if (genesis_hash_cached) {
        *blockHash = cached_genesis_hash;
        return true;
    }
    if (!getBlockHash(blockchainUtils, 0, blockHash)) {
        return false;
    }
    cached_genesis_hash = *blockHash;
    genesis_hash_cached = true;
    return true;
}

// Get Nonce

bool getNonce(BlockchainUtils *blockchainUtils, char *ss58Address, uint64_t *payloadNonce) {
    paramsArray[0] = ss58Address;
    String message = blockchainUtils->createWebsocketMessage("system_accountNextIndex", paramsArray);
    JSONVar response = blockchainUtils->rpcRequest(message);
    if (response.hasOwnProperty("error") || !response.hasOwnProperty("result")) {
        return false;
    }
    int received_nonce = (int) (response["result"]);
    Serial.print("Nonce: ");
    Serial.println(received_nonce);
    *payloadNonce = static_cast<uint64_t>(received_nonce);
    return true;
}

// Get Block Hash

bool getBlockHash(BlockchainUtils *blockchainUtils, int block_number, std::string *blockHash) {
    paramsArray[0] = block_number;
    String message = blockchainUtils->createWebsocketMessage("chain_getBlockHash", paramsArray);
    JSONVar response = blockchainUtils->rpcRequest(message);
    if (response.hasOwnProperty("error") || !response.hasOwnProperty("result")) {
        return false;
    }
    Serial.print("Block ");
    Serial.print(block_number);
    Serial.print(" hash: ");
    Serial.println(response["result"]);

    *blockHash = std::string((const char*) response["result"]);
    return true;
}

// Get Runtime Info

bool extractRuntimeVersions(BlockchainUtils *blockchainUtils, uint32_t *specVersion, uint32_t *transactionVersion) {
    if (runtime_versions_cached &&
        runtime_versions_cached_at_ms != 0 &&
        (millis() - runtime_versions_cached_at_ms) < RUNTIME_VERSIONS_CACHE_TTL_MS) {
        *specVersion = cached_spec_version;
        *transactionVersion = cached_tx_version;
        printf("[extractRuntimeVersions] cache hit spec=%u tx=%u\n",
               *specVersion, *transactionVersion);
        return true;
    }

    printf("[extractRuntimeVersions] called\n");

    JSONVar runtimeInfo;
    printf("[extractRuntimeVersions] created runtimeInfo\n");

    if (!getRuntimeInfo(blockchainUtils, &runtimeInfo)) {
        printf("[extractRuntimeVersions] getRuntimeInfo FAILED\n");
        invalidateRuntimeVersionCache();
        return false;
    }
    printf("[extractRuntimeVersions] getRuntimeInfo OK\n");

    String runtimeInfoStr = JSON.stringify(runtimeInfo);
    printf("[extractRuntimeVersions] runtimeInfo: %s\n", runtimeInfoStr.c_str());

    if (runtimeInfo.hasOwnProperty("specVersion")) {
        printf("[extractRuntimeVersions] runtimeInfo.specVersion exists\n");
        int spec = (int)runtimeInfo["specVersion"];
        printf("[extractRuntimeVersions] runtimeInfo.specVersion = %d\n", spec);
    } else {
        printf("[extractRuntimeVersions] runtimeInfo.specVersion NOT FOUND\n");
    }

    if (runtimeInfo.hasOwnProperty("transactionVersion")) {
        printf("[extractRuntimeVersions] runtimeInfo.transactionVersion exists\n");
        int tx = (int)runtimeInfo["transactionVersion"];
        printf("[extractRuntimeVersions] runtimeInfo.transactionVersion = %d\n", tx);
    } else {
        printf("[extractRuntimeVersions] runtimeInfo.transactionVersion NOT FOUND\n");
    }

    if (runtimeInfo.hasOwnProperty("specVersion") && runtimeInfo.hasOwnProperty("transactionVersion")) {
        *specVersion = static_cast<uint32_t>((int)runtimeInfo["specVersion"]);
        *transactionVersion = static_cast<uint32_t>((int)runtimeInfo["transactionVersion"]);
        cached_spec_version = *specVersion;
        cached_tx_version = *transactionVersion;
        runtime_versions_cached = true;
        runtime_versions_cached_at_ms = millis();
        printf("[extractRuntimeVersions] SUCCESS: specVersion=%u, transactionVersion=%u\n", *specVersion, *transactionVersion);
        return true;
    }

    printf("[extractRuntimeVersions] FAILED: missing keys\n");
    invalidateRuntimeVersionCache();
    return false;
}

bool getRuntimeInfo(BlockchainUtils *blockchainUtils, JSONVar *runtimeInfo) {
    std::string chainHead;
    if (!getChainHead(blockchainUtils, &chainHead)) {
        return false;
    }
    std::string parentBlockHash;
    if (!getParentBlockHash(chainHead, blockchainUtils, &parentBlockHash)) {
        return false;
    }
    return getRuntimeInfo(parentBlockHash, blockchainUtils, runtimeInfo);
}

bool getRuntimeInfo(const std::string &parentBlockHash, BlockchainUtils *blockchainUtils, JSONVar *runtimeInfo) {
    paramsArray[0] = parentBlockHash.c_str();
    String message = blockchainUtils->createWebsocketMessage("state_getRuntimeVersion", paramsArray);
    JSONVar response = blockchainUtils->rpcRequest(message);

    if (response.hasOwnProperty("error") || !response.hasOwnProperty("result")) {
        Serial.println("Error: state_getRuntimeVersion failed");
        return false;
    }

    String resultStr = JSON.stringify(response["result"]);
    *runtimeInfo = JSON.parse(resultStr);

    if (*runtimeInfo == undefined) {
        Serial.println("Error: JSON.parse failed in getRuntimeInfo");
        return false;
    }

    return true;
}

// Get Chain Head

bool getChainHead(BlockchainUtils *blockchainUtils, std::string *chainHead) {
    String message = blockchainUtils->createWebsocketMessage("chain_getHead", emptyParamsArray);
    JSONVar response = blockchainUtils->rpcRequest(message);

    if (response.hasOwnProperty("error") || !response.hasOwnProperty("result")) {
        Serial.println("Error: chain_getHead failed");
        return false;
    }
    const char* head = (const char*)(response["result"]);
    Serial.print("Chain head: ");
    Serial.println(head);
    *chainHead = std::string(head);
    return true;
}

// Get Parent Block Hash

bool getParentBlockHash(const std::string &chainHead, BlockchainUtils *blockchainUtils, std::string *parentBlockHash) {
    paramsArray[0] = chainHead.c_str();
    String message = blockchainUtils->createWebsocketMessage("chain_getHeader", paramsArray);
    JSONVar response = blockchainUtils->rpcRequest(message);

    if (response.hasOwnProperty("error") ||
        !response.hasOwnProperty("result") ||
        !response["result"].hasOwnProperty("parentHash")) {
        Serial.println("Error: chain_getHeader failed");
        return false;
    }
    const char* parent_hash = (const char*)(response["result"]["parentHash"]);
    Serial.print("Parent block hash: ");
    Serial.println(parent_hash);
    *parentBlockHash = std::string(parent_hash);
    return true;
}
