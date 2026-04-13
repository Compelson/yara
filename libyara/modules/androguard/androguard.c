/*
Copyright (c) 2015. The Koodous Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
  Changelog:
	- 2016/06/09: Start changelog and add funtions for "filters"
	- 2016/06/16: Hotfix min/max/target sdk version
	- 2016/12/12: Added certificate.not_before and certificate.not_after functions
	- 2017/01/11: Added displayed_version functions
*/

#include <jansson.h>
#include <string.h>


#include <yara/re.h>
#include <yara/modules.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#define MODULE_NAME androguard


define_function(certificate_subject_lookup)
{
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_OBJECT* obj = yr_parent();
  int result = 0;
  json_t* val = json_object_get(obj->data, "subjectDN");
  if (!val) {
    return_integer(FALSE);
  }
  
  char* value = (char*) json_string_value(val);
  if (!value) {
    return_integer(FALSE);
  }

	if (yr_re_match(ctx, regexp_argument(1), value) > 0) {
          return_integer(TRUE);
	}
  return_integer(FALSE);
}

define_function(certificate_not_before_lookup_regex)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* obj = yr_parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;

  val = json_object_get(obj->data, "not_before");
  if (val) {
	value = (char *)json_string_value(val);
  }

  if (value) {
	if (yr_re_match(ctx, regexp_argument(1), value) > 0) {
	  result = 1;
	}
  }

  return_integer(result);
}

define_function(certificate_not_before_lookup_string)
{
  YR_OBJECT* obj = yr_parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;
  val = json_object_get(obj->data, "not_before");

  if (val != NULL) {
	value = (char *)json_string_value(val);
  }

  if (value != NULL) {
	if (strcasecmp(string_argument(1), value) == 0) {
	  result = 1;
	}
  }

  return_integer(result);
}

define_function(certificate_not_after_lookup_regex)
{
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_OBJECT* obj = yr_parent();
  char* value = NULL;
  uint64_t result = 0;
  json_t *val;

  val = json_object_get(obj->data, "not_after");
  if (val) {
	value = (char *)json_string_value(val);
  }

  if (value) {
	if (yr_re_match(ctx, regexp_argument(1), value) > 0) {
	  result = 1;
	}
  }

  return_integer(result);
}

define_function(certificate_not_after_lookup_string)
{
  YR_OBJECT* obj = yr_parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;
  val = json_object_get(obj->data, "not_after");

  if (val != NULL) {
	value = (char *)json_string_value(val);    
  }
  if (value != NULL) {
	if (strcasecmp(string_argument(1), value) == 0) {
	  result = 1;
	}
  }
  return_integer(result);
}

static void remove_colon(const char* input, char* output)
{
	int i, pos_out = 0;
	for (i = 0; i < strlen(input) + 1; ++i) {
		if (input[i] != ':') {
			output[pos_out++] = input[i];
		}
	}
}

static int hexStringLookupString(YR_OBJECT* obj, const char* type, const char* argument)
{
	json_t* json = json_object_get(obj->data, type);
	if (!json) {
		return FALSE;
	}
	char* cert_str = (char*) malloc((strlen(argument) + 1) * sizeof(char));
	if (cert_str == NULL) {
		return FALSE;
	}
	remove_colon(argument, cert_str);
	char* value = (char*) json_string_value(json);
	if (value && strcasecmp(cert_str, value) == 0) {
		free(cert_str);
		return TRUE;
	}

	free(cert_str);
	return FALSE;
}

define_function(certificate_serial_lookup_string)
{
  return_integer(hexStringLookupString(yr_parent(), "serial", string_argument(1)));
}

define_function(certificate_sha1_lookup_string)
{
	return_integer(hexStringLookupString(yr_parent(), "sha1", string_argument(1)));
}

define_function(certificate_sha256_lookup_string)
{
  return_integer(
      hexStringLookupString(yr_parent(), "sha256", string_argument(1)));
}

define_function(certificate_issuer_lookup)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* obj = yr_parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;

  //json_t* mutexes_json = (json_t*) sync_obj->data;
  val = json_object_get(obj->data, "issuerDN");
  if (val) {
	value = (char *)json_string_value(val);
  }

  if (value) {
	if (yr_re_match(ctx, regexp_argument(1), value) > 0) {
	  result = 1;
	}
  }

  return_integer(result);
}

define_function(main_activity_lookup)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* obj = yr_get_object(yr_module(), "main_activity");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
	if (yr_re_match(ctx, regexp_argument(1), value) > 0) {
	  result = 1;
	}
  }
 
  return_integer(result);
}

define_function(permission_lookup)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* obj = yr_get_object(yr_module(), "permission");
  struct permissions *a;

  a = obj->data;
  if (a == NULL) { return_integer(0); }
  
  json_t* list_perms = (json_t*) a->permissions;
  json_t* list_new_perms = (json_t*) a->new_permissions;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list_perms, index, value)
  {
	if (yr_re_match(ctx, regexp_argument(1), json_string_value(value)) > 0)
	{
	  result = 1;
	  break;
	}
  }

  //Or try with new_permissions
  if (!result) {
	json_array_foreach(list_new_perms, index, value)
	{
	  if (yr_re_match(ctx, regexp_argument(1), json_string_value(value)) > 0)
	  {
		result = 1;
		break;
	  }
	}
  }
  return_integer(result);
}

define_function(activity_lookup_regex)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* activity_obj = yr_get_object(yr_module(), "activity");
  json_t* list = (json_t*) activity_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (yr_re_match(ctx, regexp_argument(1), json_string_value(value)) > 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(activity_lookup_string)
{
  YR_OBJECT* activity_obj = yr_get_object(yr_module(), "activity");
  json_t* list = (json_t*) activity_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(service_lookup_regex)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* service_obj = yr_get_object(yr_module(), "service");
  json_t* list = (json_t*) service_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (yr_re_match(ctx, regexp_argument(1), json_string_value(value)) > 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(service_lookup_string)
{
  YR_OBJECT* service_obj = yr_get_object(yr_module(), "service");
  json_t* list = (json_t*) service_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(filter_lookup_regex)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* filter_obj = yr_get_object(yr_module(), "filter");
  json_t* list = (json_t*) filter_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (yr_re_match(ctx, regexp_argument(1), json_string_value(value)) > 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(filter_lookup_string)
{
  YR_OBJECT* filter_obj = yr_get_object(yr_module(), "filter");
  json_t* list = (json_t*) filter_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(receiver_lookup_regex)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* receiver_obj = yr_get_object(yr_module(), "receiver");
  json_t* list = (json_t*) receiver_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (yr_re_match(ctx, regexp_argument(1), json_string_value(value)) > 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(receiver_lookup_string)
{
  YR_OBJECT* receiver_obj = yr_get_object(yr_module(), "receiver");
  json_t* list = (json_t*) receiver_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(displayed_version_lookup_regex)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* obj = yr_get_object(yr_module(), "displayed_version");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
	if (yr_re_match(ctx, regexp_argument(1), value) > 0) {
	  result = 1;
	}
  }
 
  return_integer(result);
}

define_function(displayed_version_lookup_string)
{
  YR_OBJECT* obj = yr_get_object(yr_module(), "displayed_version");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
	if (strcasecmp(string_argument(1), value) == 0) {
	  result = 1;
	}
  }
 
  return_integer(result);
}

define_function(url_lookup_regex)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* obj = yr_get_object(yr_module(), "url");
  json_t* list = (json_t*) obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (yr_re_match(ctx, regexp_argument(1), json_string_value(value)) > 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(url_lookup_string)
{
  YR_OBJECT* obj = yr_get_object(yr_module(), "url");
  json_t* list = (json_t*) obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
	if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
	{
	  result = 1;
	  break;
	}
  }
  return_integer(result);
}

define_function(appname_lookup_regex)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* obj = yr_get_object(yr_module(), "app_name");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
	if (yr_re_match(ctx, regexp_argument(1), value) > 0) {
	  result = 1;
	}
  }

  return_integer(result);
}

define_function(appname_lookup_string)
{
  YR_OBJECT* obj = yr_get_object(yr_module(), "app_name");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
	if (strcasecmp(string_argument(1), value) == 0) {
	  result = 1;
	}
  }

  return_integer(result);
}

define_function(package_name_lookup_regex)
{
  YR_SCAN_CONTEXT *ctx = yr_scan_context();
  YR_OBJECT* package_name_obj = yr_get_object(yr_module(), "package_name");
  char* value = package_name_obj->data;
  uint64_t result = 0;

  if (value) {
	if (yr_re_match(ctx, regexp_argument(1), value) > 0) {
	  result = 1;
	}
  }

  return_integer(result);
}

define_function(package_name_lookup_string)
{
  YR_OBJECT* package_name_obj = yr_get_object(yr_module(), "package_name");
  char* value = package_name_obj->data;
  uint64_t result = 0;

  if (value) {
	if (strcasecmp(string_argument(1), value) == 0) {
	  result = 1;
	}
  }

  return_integer(result);
}

////////////////////////
/*
  Declarations
*/
begin_declarations;
  declare_function("activity", "r", "i", activity_lookup_regex);
  declare_function("activity", "s", "i", activity_lookup_string);

  declare_string("app_name");
  declare_function("app_name", "r", "i", appname_lookup_regex);
  declare_function("app_name", "s", "i", appname_lookup_string);

  begin_struct("certificate");
	declare_function("issuer", "r", "i", certificate_issuer_lookup);
	declare_function("not_after", "r", "i", certificate_not_after_lookup_regex);
	declare_function("not_after", "s", "i", certificate_not_after_lookup_string);
	declare_function("not_before", "r", "i", certificate_not_before_lookup_regex);
	declare_function("not_before", "s", "i", certificate_not_before_lookup_string);

	declare_string("serial");
	declare_function("serial", "s", "i", certificate_serial_lookup_string);

	declare_function("sha1", "s", "i", certificate_sha1_lookup_string);
	declare_function("sha256", "s", "i", certificate_sha256_lookup_string);

	declare_function("subject", "r", "i", certificate_subject_lookup);
  end_struct("certificate");

  declare_integer("max_sdk");
  declare_integer("min_sdk");
  declare_integer("target_sdk");

  declare_string("displayed_version");
  declare_function("displayed_version", "r", "i", displayed_version_lookup_regex);
  declare_function("displayed_version", "s", "i", displayed_version_lookup_string);

  declare_function("filter", "r", "i", filter_lookup_regex);
  declare_function("filter", "s", "i", filter_lookup_string);

  declare_function("main_activity", "r", "i", main_activity_lookup_regex);
  declare_function("main_activity", "s", "i", main_activity_lookup_string);

  declare_string("package_name");
  declare_function("package_name", "r", "i", package_name_lookup_regex);
  declare_function("package_name", "s", "i", package_name_lookup_string);

  // From both "uses" and "new" permissions
  declare_integer("permissions_number");
  declare_function("permission", "r", "i", permission_lookup_regex);
  declare_function("permission", "s", "i", permission_lookup_string);

  declare_integer("uses_permissions_number");
  declare_function("uses_permission", "r", "i", usesPermission_lookup_regex);
  declare_function("uses_permission", "s", "i", usesPermission_lookup_string);
  
  declare_integer("new_permissions_number");
  declare_function("new_permission", "r", "i", newPermission_lookup_regex);
  declare_function("new_permission", "s", "i", newPermission_lookup_string);


  declare_function("receiver", "r", "i", receiver_lookup_regex);
  declare_function("receiver", "s", "i", receiver_lookup_string);

  declare_function("service", "r", "i", service_lookup_regex);
  declare_function("service", "s", "i", service_lookup_string);

  declare_function("url", "r", "i", url_lookup_regex);
  declare_function("url", "s", "i", url_lookup_string);

end_declarations;

/*
  Initialize module
*/
int module_initialize(
	YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

/*
  Finalize module
*/
int module_finalize(
	YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


/*
  Module load
*/
int module_load(
	YR_SCAN_CONTEXT* context,
	YR_OBJECT* module_object,
	void* module_data,
	size_t module_data_size)
{
  json_error_t json_error;
  const char* str_val = NULL;
  json_t* json = NULL;

  /* End definitions */
  if (module_data == NULL) {
	return ERROR_SUCCESS;
  }

  json = json_loadb((const char*) module_data, module_data_size, JSON_ALLOW_NUL, &json_error);
  if (json == NULL) {
	return ERROR_INVALID_MODULE_DATA;
  }

  // Application name
  YR_OBJECT* appName_obj = NULL;
  char* appName = (char*) json_string_value(json_object_get(json, "app_name"));
  appName_obj = yr_get_object(module_object, "app_name");
  appName_obj->data = appName;
  yr_set_string(appName, module_data, "app_name");

  // Min SDK version
  int32_t minSdkVer = json_integer_value(json_object_get(json, "min_sdk_version"));
  yr_set_integer(minSdkVer, module_object, "min_sdk");

  // Max SDK version
  int32_t maxSdkVer = json_integer_value(json_object_get(json, "max_sdk_version"));
  yr_set_integer(maxSdkVer, module_object, "max_sdk");

  // Target SDK verions
  int32_t targetSdkVersion = json_integer_value(json_object_get(json, "target_sdk_version"));
  yr_set_integer(targetSdkVersion, module_object, "target_sdk");

  // Main activity -- POLAK_TODO: get the data from the json, but there can be more values, so proper lookup is neede
  YR_OBJECT* mainActivity_obj = yr_get_object(module_object, "main_activity");
  mainActivity_obj->data = (char*)json_string_value(json_object_get(json, "main_activities"));

  // Displayed versions
  YR_OBJECT* displayedVersion_obj = yr_get_object(module_object, "displayed_version");
  displayedVersion_obj->data = (char*)json_string_value(json_object_get(json, "displayed_version"));

  // Package name
  YR_OBJECT* packageName_obj = yr_get_object(module_object, "package_name");
  packageName_obj->data = (char*) json_string_value(json_object_get(json, "package_name"));

  // Uses Permissions (from <uses-permission>)
  YR_OBJECT* usesPermission_obj = yr_get_object(module_object, "uses_permission");
  usesPermission_obj->data = (void*) json_object_get(json, "permissions_uses");
  int usesPermissionsNumber = json_array_size(usesPermission_obj->data);
  yr_set_integer(usesPermissionsNumber, module_object, "uses_permissions_number");

  // New permissions (from <permission>)
  YR_OBJECT* newPermission_obj = yr_get_object(module_object, "new_permission");
  newPermission_obj->data = (void*)json_object_get(json, "permissions_new");
  int newPermissionsNumber = json_array_size(newPermission_obj->data);
  yr_set_integer(newPermissionsNumber, module_object, "new_permissions_number");

  // Total permissions number
  yr_set_integer(usesPermissionsNumber + newPermissionsNumber, module_object, "permissions_number");


  // Other structures
  YR_OBJECT* activity_obj = yr_get_object(module_object, "activity");
  YR_OBJECT* certificate_obj = yr_get_object(module_object, "certificate");
  YR_OBJECT* filter_obj = yr_get_object(module_object, "filter");
  YR_OBJECT* receiver_obj = yr_get_object(module_object, "receiver");
  YR_OBJECT* service_obj = yr_get_object(module_object, "service");
  YR_OBJECT* url_obj = yr_get_object(module_object, "url");

  activity_obj->data = json_object_get(json, "activities");
  certificate_obj->data = json_object_get(json, "certificates");
  filter_obj->data = json_object_get(json, "filters");
  receiver_obj->data = json_object_get(json, "receivers");
  service_obj->data = json_object_get(json, "services");
  url_obj->data = json_object_get(json, "urls");

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
  YR_OBJECT* obj;
  if (module->data != NULL) {
	json_decref((json_t*)module->data);
  }

  return ERROR_SUCCESS;
}
