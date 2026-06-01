#include <Arduino.h>
#include <Robonomics.h>

Robonomics robonomics;

void setup() {
  Serial.begin(115200);

  delay(3000);

  Serial.println("Starting set_devices example");

  robonomics.generateAndSetPrivateKey();
  
}

void loop() {
  delay(2000);
  Serial.println("Alive");
}