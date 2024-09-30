#include "cJSON.h"

char* create_chat_message(const char* message, const char* iv, const char* ciphertext) {
    cJSON *json = cJSON_CreateObject();
    if (!json) {
        printf("Failed to create JSON object\n");
        return NULL;
    }

    cJSON_AddStringToObject(json, "type", "chat");
    cJSON_AddStringToObject(json, "iv", iv);
    cJSON_AddStringToObject(json, "ciphertext", ciphertext);

    char* json_str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    return json_str; // Remember to free this string after sending it!
}
