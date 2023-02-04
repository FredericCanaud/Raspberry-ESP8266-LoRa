#include <stdio.h>
#include <string.h>
#include "mgos.h"
#include "mgos_mqtt.h"

static void my_timer_cb(void *arg) {
char* message = "Bonjour !";
mgos_mqtt_pub("/esp8266", message, strlen(message), 1, 0);
(void) arg;
}

enum mgos_app_init_result mgos_app_init(void) {
mgos_set_timer(2000, MGOS_TIMER_REPEAT, my_timer_cb, NULL);
return MGOS_APP_INIT_SUCCESS;
}
