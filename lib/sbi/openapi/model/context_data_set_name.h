/*
 * context_data_set_name.h
 *
 *
 */

#ifndef _OpenAPI_context_data_set_name_H_
#define _OpenAPI_context_data_set_name_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_context_data_set_name_s OpenAPI_context_data_set_name_t;
typedef struct OpenAPI_context_data_set_name_s {
} OpenAPI_context_data_set_name_t;

OpenAPI_context_data_set_name_t *OpenAPI_context_data_set_name_create(
    );
void OpenAPI_context_data_set_name_free(OpenAPI_context_data_set_name_t *context_data_set_name);
OpenAPI_context_data_set_name_t *OpenAPI_context_data_set_name_parseFromJSON(cJSON *context_data_set_nameJSON);
cJSON *OpenAPI_context_data_set_name_convertToJSON(OpenAPI_context_data_set_name_t *context_data_set_name);
OpenAPI_context_data_set_name_t *OpenAPI_context_data_set_name_copy(OpenAPI_context_data_set_name_t *dst, OpenAPI_context_data_set_name_t *src);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_context_data_set_name_H_ */

