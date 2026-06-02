#include "Extrinsic.h"
#include "blake/blake2.h"

// Robonomics runtime (specVersion=42) uses TxExtension tuple (see runtime/robonomics/src/lib.rs):
// CheckEra, CheckNonce, ChargeTransactionPayment, CheckMetadataHash
// Many "Check*" extensions encode as empty (()), but Era/Nonce/Payment/MetadataHash do encode bytes.

static inline Data encodeEraBytes(uint32_t era) {
    // For now we only support Immortal era (single 0x00 byte).
    // Our firmware currently passes era as a u32 from getEra(); using Immortal is enough for now.
    (void)era;
    return Data{0x00};
}

static inline Data encodeMetadataHashNone() {
    // frame_metadata_hash_extension::CheckMetadataHash uses Option<H256>.
    // None = 0x00
    return Data{0x00};
}

static inline Data encodeChargeTransactionPayment(uint64_t tip) {
    // Robonomics runtime expects ChargeTransactionPayment encoding with a single `tip` field.
    // (Polkadot.js signed extrinsic shows only 1 byte tip=0x00 when tip=0.)
    return encodeCompact(tip);
}

std::vector<uint8_t> doPayload (Data call, uint32_t era, uint64_t nonce, uint64_t tip, uint32_t sv, uint32_t tv, std::string gen, std::string block) {
    Data data;
    append(data, call);
    // SignedExtra (for payload) - only the parts that are "signed" are included here,
    // plus additional_signed fields (specVersion/txVersion/genesis/block hash, and optionally metadata hash).
    append(data, encodeEraBytes(era));
    // Serial.print("After era: ");
    // for (int k = 0; k < data.size(); k++) 
    //     Serial.printf("%02x", data[k]);
    // Serial.println("");

    append(data, encodeCompact(nonce));
    // Serial.print("After nonce: ");
    // for (int k = 0; k < data.size(); k++) 
    //     Serial.printf("%02x", data[k]);
    // Serial.println("");
    // ChargeTransactionPayment
    append(data, encodeChargeTransactionPayment(tip));
    // CheckMetadataHash extra: Option<H256>
    append(data, encodeMetadataHashNone());
    // Serial.print("After tip: ");
    // for (int k = 0; k < data.size(); k++) 
    //     Serial.printf("%02x", data[k]);
    // Serial.println("");
              
    encode32LE(sv, data);     // specversion
    // Serial.print("After specver: ");
    // for (int k = 0; k < data.size(); k++) 
    //     Serial.printf("%02x", data[k]);
    // Serial.println("");
    encode32LE(tv, data);     // version
    // Serial.print("After txver: ");
    // for (int k = 0; k < data.size(); k++) 
    //     Serial.printf("%02x", data[k]);
    // Serial.println("");
            
    std::vector<uint8_t> gh = hex2bytes(gen.c_str());
    append(data, gh);
    // Serial.print("After genesis hash: ");
    // for (int k = 0; k < data.size(); k++) 
    //     Serial.printf("%02x", data[k]);
    // Serial.println("");
    std::vector<uint8_t> bh = hex2bytes(block.c_str()); // block hash
    append(data, bh);     
    // Serial.print("After block hash: ");
    // for (int k = 0; k < data.size(); k++) 
    //     Serial.printf("%02x", data[k]);
    // Serial.println("");

    // CheckMetadataHash additional_signed: Option<H256>
    append(data, encodeMetadataHashNone());
    return data;
}

std::vector<uint8_t> doSign(Data data, uint8_t privateKey[32], uint8_t publicKey[32]) {
    uint8_t sig[SIGNATURE_SIZE];
    uint8_t payloadHash[32];
    const uint8_t* payload = data.data();
    size_t payloadSize = data.size();

    // Substrate SignedPayload hashes payloads longer than 256 bytes before signing.
    if (payloadSize > 256) {
        blake2(payloadHash, sizeof(payloadHash), payload, payloadSize, NULL, 0);
        payload = payloadHash;
        payloadSize = sizeof(payloadHash);
    }

#ifndef UNIT_TEST
    Ed25519::sign(sig, privateKey, publicKey, payload, payloadSize);
#else
    //do like Arduino Ed25519::sign() for unit test, i.e. by crypto++ library
    CryptoPP::Donna::ed25519_sign(payload, payloadSize, privateKey, publicKey, sig);
#endif
    std::vector<byte> signature (sig,sig + SIGNATURE_SIZE);   // signed data as bytes vector
    return signature;
}

std::vector<uint8_t> doEncode (Data signature, Data signerAddress, uint32_t era, uint64_t nonce, uint64_t tip, Data call) {
    Data edata;
    append(edata, Data{extrinsicFormat | signedBit});  // version header

    // Signer: MultiAddress (usually AccountId)
    append(edata, signerAddress);
    append(edata, sigTypeEd25519); // signature type
    append(edata, signature);      // signatured payload
              
    // SignedExtra (TxExtension):
    // CheckEra, CheckNonce, ChargeTransactionPayment, CheckMetadataHash.
    append(edata, encodeEraBytes(era));
    append(edata, encodeCompact(nonce));
    append(edata, encodeChargeTransactionPayment(tip));
    append(edata, encodeMetadataHashNone());
  
    append(edata, call);
    encodeLengthPrefix(edata); // append length
              
    return edata;
}
