#pragma once

#include "config.h"

#ifdef ROBONOMICS_USE_HTTP
#ifdef ESP32
#include <WiFi.h>
#include <WiFiClientSecure.h>
#endif
#ifdef ESP8266
#include <ESP8266WiFi.h>
#include <WiFiClientSecureBearSSL.h>
#endif
#include <Arduino_JSON.h>

/** Per-request connect + read timeout (ms). Must be below firmware datalog watchdog. */
#ifndef ROBONOMICS_HTTP_TIMEOUT_MS
#define ROBONOMICS_HTTP_TIMEOUT_MS 45000UL
#endif
/** Max JSON-RPC response body size. */
#ifndef ROBONOMICS_HTTP_MAX_BODY_BYTES
#define ROBONOMICS_HTTP_MAX_BODY_BYTES 16384UL
#endif

class HTTPRequests {
    private:
        // Must outlive HTTPClient::begin(...) and POST().
#ifdef ESP32
        WiFiClient plain_client_;
        WiFiClientSecure secure_client_;
#endif
#ifdef ESP8266
        WiFiClient plain_client_;
        BearSSL::WiFiClientSecure secure_client_;
#endif
        String node_url;
    public:
        void setup(String host);
        void disconnect();
        JSONVar sendRequest(String message);
};

#endif