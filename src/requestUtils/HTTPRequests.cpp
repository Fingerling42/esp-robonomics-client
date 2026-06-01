#include "config.h"

#ifdef ROBONOMICS_USE_HTTP

#include <Arduino.h>
#include "HTTPRequests.h"
#ifdef ESP32
#include <HTTPClient.h>
#endif
#ifdef ESP8266
#include <ESP8266HTTPClient.h>
#endif

static String normalizeRpcUrl(String input) {
    input.trim();

    // If user pasted full URL, keep scheme+path. Otherwise treat as host.
    bool has_scheme = input.startsWith("http://") || input.startsWith("https://");
    if (!has_scheme) {
        // User provided host only: default to https.
        input = "https://" + input;
    }

    // Strip trailing spaces and slashes.
    while (input.endsWith(" ")) input.remove(input.length() - 1);
    while (input.endsWith("/")) input.remove(input.length() - 1);

    // Ensure /rpc/ suffix (Robonomics nodes serve JSON-RPC here).
    // If already includes /rpc or /rpc/, don't duplicate.
    if (!(input.endsWith("/rpc") || input.endsWith("/rpc/"))) {
        input += "/rpc";
    }
    if (!input.endsWith("/")) input += "/";

    return input;
}

void HTTPRequests::setup(String host) {
    // Accept both:
    // - "polkadot.rpc.robonomics.network"
    // - "https://polkadot-kz.rpc.robonomics.network/"
    // - "http://.../rpc/" (may redirect to https on some mirrors)
    node_url = normalizeRpcUrl(host);
    Serial.print("[HTTP] RPC URL: ");
    Serial.println(node_url);
}

void HTTPRequests::disconnect() {
#ifdef ESP32
    plain_client_.stop();
    secure_client_.stop();
#endif
#ifdef ESP8266
    plain_client_.stop();
    secure_client_.stop();
#endif
}

/** Read HTTP body with deadline; avoids blocking forever in getString() on half-open SSL. */
static bool readResponseBody(HTTPClient& http, String& payload) {
    payload = "";
    WiFiClient* stream = http.getStreamPtr();
    if (stream == nullptr) {
        Serial.println("[HTTP] no response stream");
        return false;
    }
    const unsigned long deadline = millis() + ROBONOMICS_HTTP_TIMEOUT_MS;
    while (millis() < deadline) {
        while (stream->available() > 0 && payload.length() < (int)ROBONOMICS_HTTP_MAX_BODY_BYTES) {
            const int c = stream->read();
            if (c < 0) {
                break;
            }
            payload += static_cast<char>(c);
        }
        if (!http.connected() && stream->available() <= 0) {
            break;
        }
        delay(2);
        yield();
    }
    if (payload.length() == 0) {
        Serial.println("[HTTP] response body empty or read timeout");
        return false;
    }
    if (millis() >= deadline && (http.connected() || stream->available() > 0)) {
        Serial.println("[HTTP] response body read timeout (truncated)");
    }
    return true;
}

static void configureHttpClient(HTTPClient& http) {
    http.setReuse(false);
#ifdef ESP32
    http.setTimeout(ROBONOMICS_HTTP_TIMEOUT_MS);
    http.setConnectTimeout(ROBONOMICS_HTTP_TIMEOUT_MS);
#endif
}

JSONVar HTTPRequests::sendRequest(String message) {
    Serial.print("[HTTP]+POST:\n"); 
    JSONVar response;
    HTTPClient http;
    const bool is_https = node_url.startsWith("https://");

    // Collect Location header for manual redirect retry.
    const char* header_keys[] = {"Location"};
    http.collectHeaders(header_keys, 1);

#ifdef ESP32
    if (is_https) {
        secure_client_.setInsecure();
        http.begin(secure_client_, node_url.c_str());
    } else {
        http.begin(plain_client_, node_url.c_str());
    }
#endif

#ifdef ESP8266
    if (is_https) {
        secure_client_.setInsecure();
        http.begin(secure_client_, node_url.c_str());
    } else {
        http.begin(plain_client_, node_url.c_str());
    }
#endif

    configureHttpClient(http);
    http.addHeader("Content-Type", "application/json");
    uint32_t httpCode = (uint32_t)http.POST(message);
    Serial.println("sent:");
    Serial.println(message);
    if (httpCode > 0) {
        Serial.printf("[HTTP]+POST code: %d\n", httpCode);
        if (httpCode == HTTP_CODE_OK) {
            String payload;
            if (!readResponseBody(http, payload)) {
                response["error"] = "body_read_timeout";
            } else {
                Serial.println("received:");
                Serial.println(payload);
                response = JSON.parse(payload);
            }
        } else if (httpCode == 301 || httpCode == 302 || httpCode == 307 || httpCode == 308) {
            // Some mirrors redirect http->https or "/"->"/rpc/".
            String location = http.header("Location");
            if (location.length() > 0) {
                Serial.print("[HTTP]+POST redirect Location: ");
                Serial.println(location);

                // Retry once using redirected URL (normalized to ensure /rpc/).
                HTTPClient http2;
                String retry_url = normalizeRpcUrl(location);
                const bool retry_https = retry_url.startsWith("https://");

                const char* header_keys2[] = {"Location"};
                http2.collectHeaders(header_keys2, 1);

#ifdef ESP32
                if (retry_https) {
                    secure_client_.setInsecure();
                    http2.begin(secure_client_, retry_url.c_str());
                } else {
                    http2.begin(plain_client_, retry_url.c_str());
                }
#endif

#ifdef ESP8266
                if (retry_https) {
                    secure_client_.setInsecure();
                    http2.begin(secure_client_, retry_url.c_str());
                } else {
                    http2.begin(plain_client_, retry_url.c_str());
                }
#endif

                configureHttpClient(http2);
                http2.addHeader("Content-Type", "application/json");
                uint32_t httpCode2 = (uint32_t)http2.POST(message);
                Serial.printf("[HTTP]+POST retry code: %d\n", httpCode2);
                if (httpCode2 == HTTP_CODE_OK) {
                    String payload2;
                    if (!readResponseBody(http2, payload2)) {
                        response["error"] = "body_read_timeout";
                    } else {
                        Serial.println("received:");
                        Serial.println(payload2);
                        response = JSON.parse(payload2);
                    }
                } else {
                    Serial.println("HTTP response is not 200 (after redirect retry)");
                    response["error"] = httpCode2;
                }
                http2.end();
            } else {
                Serial.println("HTTP response is redirect but no Location header");
                response["error"] = httpCode;
            }
        } else {
            Serial.println("HTTP response is not 200");
            response["error"] = httpCode;
        }
    } else {
        Serial.println("HTTP response is 0");
        response["error"] = httpCode;
    }
    http.end();
    return response;
}

#endif