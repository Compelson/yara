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

#include <ctype.h>

#include <yara/re.h>
#include <yara/modules.h>

#ifdef _WIN32
#define memcasecmp _memicmp
#endif

#define MODULE_NAME androguard

static int generalLookupFromEntryRegex(YR_SCAN_CONTEXT* ctx, YR_OBJECT* obj, RE* re)
{
	return json_string_length(obj->data) && yr_re_match(ctx, re, json_string_value(obj->data)) > 0;
}

static int generalLookupFromEntryString(YR_OBJECT* obj, SIZED_STRING* ss)
{
	if (ss->length == 0) {
		return FALSE;
	}
	return json_string_length(obj->data) == ss->length && memcasecmp(ss->c_string, json_string_value(obj->data), ss->length) == 0;
}

static int generalLookupFromListRegex(YR_SCAN_CONTEXT* ctx, YR_OBJECT* obj, RE* re)
{
	json_t* list = (json_t*) obj->data;
	size_t index;
	json_t* value;
	json_array_foreach(list, index, value) {
		if (yr_re_match(ctx, re, json_string_value(value)) > 0) {
			return TRUE;
		}
	}
	return FALSE;
}

static int generalLookupFromListString(YR_OBJECT* obj, SIZED_STRING* ss)
{
	if (ss->length == 0) {
		return FALSE;
	}
	json_t* list = (json_t*) obj->data;
	size_t index;
	json_t* value;
	json_array_foreach(list, index, value) {
		if (json_string_length(value) != ss->length) {
			continue;
		}
		if (memcasecmp(ss->c_string, json_string_value(value), ss->length) == 0) {
			return TRUE;
		}
	}
	return FALSE;
}

static size_t removeChar(char* input, size_t len, char c)
{
	char* read = input;
	char* write = input;
	char* end = input + len;
	while (read < end) {
		if (*read != c) {
			*write = *read;
			++write;
		}
		++read;
	}
	return (size_t)(write - input);
}

static int certificatePropertyLookupRegex(YR_SCAN_CONTEXT* ctx, YR_OBJECT* obj, const char* property, RE* re)
{
	json_t* certsList = (json_t*) obj->data;
	size_t index;
	json_t* cert;
	json_array_foreach(certsList, index, cert) {
		char* certProperty = (char*)json_string_value(json_object_get(cert, property));
		if (certProperty && yr_re_match(ctx, re, certProperty) > 0) {
			return TRUE;
		}
	}
	return FALSE;
}

static int certificatePropertyLookupString(YR_OBJECT* obj, const char* property, SIZED_STRING* ss)
{
	if (ss->length == 0) {
		return FALSE;
	}

	json_t* certsList = (json_t*) obj->data;
	size_t index;
	json_t* cert;
	json_array_foreach(certsList, index, cert) {
		json_t* propertyJson = json_object_get(cert, property);
		if (!propertyJson || json_string_length(propertyJson) != ss->length) {
			continue;
		}
		if (memcasecmp(ss->c_string, json_string_value(propertyJson), ss->length) == 0) {
			return TRUE;
		}
	}
	return FALSE;
}

#pragma region Certificates
define_function(certificate_issuer_lookup_regex)
{
	return_integer(certificatePropertyLookupRegex(yr_scan_context(), yr_parent(), "issuerDN", regexp_argument(1)));
}

define_function(certificate_issuer_lookup_string)
{
	return_integer(certificatePropertyLookupString(yr_parent(), "issuerDN", sized_string_argument(1)));
}

define_function(certificate_not_after_lookup_regex)
{
	return_integer(certificatePropertyLookupRegex(yr_scan_context(), yr_parent(), "not_after", regexp_argument(1)));
}

define_function(certificate_not_after_lookup_string)
{
	return_integer(certificatePropertyLookupString(yr_parent(), "not_after", sized_string_argument(1)));
}

define_function(certificate_not_before_lookup_regex)
{
	return_integer(certificatePropertyLookupRegex(yr_scan_context(), yr_parent(), "not_before", regexp_argument(1)));
}

define_function(certificate_not_before_lookup_string)
{
	return_integer(certificatePropertyLookupString(yr_parent(), "not_before", sized_string_argument(1)));
}

define_function(certificate_serial_lookup_string)
{
	return_integer(certificatePropertyLookupString(yr_parent(), "serial", sized_string_argument(1)));
}

define_function(certificate_sha1_lookup_string)
{
	SIZED_STRING* ss = sized_string_argument(1);
	ss->length = removeChar(ss->c_string, ss->length, ':');
	return_integer(certificatePropertyLookupString(yr_parent(), "sha1", ss));
}

define_function(certificate_sha256_lookup_string)
{
	SIZED_STRING* ss = sized_string_argument(1);
	ss->length = removeChar(ss->c_string, ss->length, ':');
	return_integer(certificatePropertyLookupString(yr_parent(), "sha256", ss));
}

define_function(certificate_subject_lookup_regex)
{
	return_integer(certificatePropertyLookupRegex(yr_scan_context(), yr_parent(), "subjectDN", regexp_argument(1)));
}

define_function(certificate_subject_lookup_string)
{
	return_integer(certificatePropertyLookupString(yr_parent(), "subjectDN", sized_string_argument(1)));
}
#pragma endregion // Certificates

#pragma region Permissions

// All permissions
define_function(permission_lookup_string)
{
	YR_OBJECT* usesPermissions_obj = yr_get_object(yr_module(), "uses_permission");
	YR_OBJECT* newPermissions_obj = yr_get_object(yr_module(), "new_permission");
	if (generalLookupFromListString(usesPermissions_obj, sized_string_argument(1)) == 1) {
		return_integer(TRUE);
	}
	if (generalLookupFromListString(newPermissions_obj, sized_string_argument(1)) == 1) {
		return_integer(TRUE);
	}
	return_integer(FALSE);
}

define_function(permission_lookup_regex)
{
	YR_SCAN_CONTEXT* ctx = yr_scan_context();
	YR_OBJECT* usesPermissions_obj = yr_get_object(yr_module(), "uses_permission");
	YR_OBJECT* newPermissions_obj = yr_get_object(yr_module(), "new_permission");
	if (generalLookupFromListRegex(ctx, usesPermissions_obj, regexp_argument(1)) == 1) {
		return_integer(TRUE);
	}
	if (generalLookupFromListRegex(ctx, newPermissions_obj, regexp_argument(1)) == 1) {
		return_integer(TRUE);
	}
	return_integer(FALSE);
}

// Just "uses" permissions
define_function(usesPermission_lookup_string)
{
	YR_OBJECT* usesPermissions_obj = yr_get_object(yr_module(), "uses_permission");
	return_integer(generalLookupFromListString(usesPermissions_obj, sized_string_argument(1)));
}

define_function(usesPermission_lookup_regex)
{
	YR_OBJECT* usesPermissions_obj = yr_get_object(yr_module(), "uses_permission");
	return_integer(generalLookupFromListRegex(yr_scan_context(), usesPermissions_obj, regexp_argument(1)));
}

// Just "new" permissions
define_function(newPermission_lookup_string)
{
	YR_OBJECT* newPermissions_obj = yr_get_object(yr_module(), "new_permission");
	return_integer(generalLookupFromListString(newPermissions_obj, sized_string_argument(1)));
}

define_function(newPermission_lookup_regex)
{
	YR_OBJECT* newPermissions_obj = yr_get_object(yr_module(), "new_permission");
	return_integer(generalLookupFromListRegex(yr_scan_context(), newPermissions_obj, regexp_argument(1)));
}
#pragma endregion // Permissions

#pragma region LookupsFromEntries
define_function(appname_lookup_regex)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "app_name");
	return_integer(generalLookupFromEntryRegex(yr_scan_context(), obj, regexp_argument(1)));
}

define_function(appname_lookup_string)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "app_name");
	return_integer(generalLookupFromEntryString(obj, sized_string_argument(1)));
}

define_function(displayed_version_lookup_regex)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "displayed_version");
	return_integer(generalLookupFromEntryRegex(yr_scan_context(), obj, regexp_argument(1)));
}

define_function(displayed_version_lookup_string)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "displayed_version");
	return_integer(generalLookupFromEntryString(obj, sized_string_argument(1)));
}

define_function(package_name_lookup_regex)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "package_name");
	return_integer(generalLookupFromEntryRegex(yr_scan_context(), obj, regexp_argument(1)));
}

define_function(package_name_lookup_string)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "package_name");
	return_integer(generalLookupFromEntryString(obj, sized_string_argument(1)));
}
#pragma endregion // LookupsFromEntries

#pragma region LookupsFromLists
define_function(activity_lookup_regex)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "activity");
	return_integer(generalLookupFromListRegex(yr_scan_context(), obj, regexp_argument(1)));
}

define_function(activity_lookup_string)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "activity");
	return_integer(generalLookupFromListString(obj, sized_string_argument(1)));
}

define_function(filter_lookup_regex)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "filter");
	return_integer(generalLookupFromListRegex(yr_scan_context(), obj, regexp_argument(1)));
}

define_function(filter_lookup_string)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "filter");
	return_integer(generalLookupFromListString(obj, sized_string_argument(1)));
}

define_function(main_activity_lookup_regex)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "main_activity");
	return_integer(generalLookupFromListRegex(yr_scan_context(), obj, regexp_argument(1)));
}

define_function(main_activity_lookup_string)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "main_activity");
	return_integer(generalLookupFromListString(obj, sized_string_argument(1)));
}

define_function(receiver_lookup_regex)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "receiver");
	return_integer(generalLookupFromListRegex(yr_scan_context(), obj, regexp_argument(1)));
}

define_function(receiver_lookup_string)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "receiver");
	return_integer(generalLookupFromListString(obj, sized_string_argument(1)));
}

define_function(service_lookup_regex)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "service");
	return_integer(generalLookupFromListRegex(yr_scan_context(), obj, regexp_argument(1)));
}

define_function(service_lookup_string)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "service");
	return_integer(generalLookupFromListString(obj, sized_string_argument(1)));
}

define_function(url_lookup_regex)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "url");
	return_integer(generalLookupFromListRegex(yr_scan_context(), obj, regexp_argument(1)));
}

define_function(url_lookup_string)
{
	YR_OBJECT* obj = yr_get_object(yr_module(), "url");
	return_integer(generalLookupFromListString(obj, sized_string_argument(1)));
}
#pragma endregion // LookupsFromLists

#pragma region ModuleDeclaration
begin_declarations;
	// Versions
	declare_integer("max_sdk");
	declare_integer("min_sdk");
	declare_integer("target_sdk");
	
	// Certificates
	begin_struct("certificate");
		declare_function("issuer", "r", "i", certificate_issuer_lookup_regex);
		declare_function("issuer", "s", "i", certificate_issuer_lookup_string);
		declare_function("not_after", "r", "i", certificate_not_after_lookup_regex);
		declare_function("not_after", "s", "i", certificate_not_after_lookup_string);
		declare_function("not_before", "r", "i", certificate_not_before_lookup_regex);
		declare_function("not_before", "s", "i", certificate_not_before_lookup_string);
		declare_function("serial", "s", "i", certificate_serial_lookup_string);
		declare_function("sha1", "s", "i", certificate_sha1_lookup_string);
		declare_function("sha256", "s", "i", certificate_sha256_lookup_string);
		declare_function("subject", "r", "i", certificate_subject_lookup_regex);
		declare_function("subject", "s", "i", certificate_subject_lookup_string);
	end_struct("certificate");

	// Permissions
	declare_integer("permissions_number");
	declare_function("permission", "r", "i", permission_lookup_regex);
	declare_function("permission", "s", "i", permission_lookup_string);

	declare_integer("uses_permissions_number");
	declare_function("uses_permission", "r", "i", usesPermission_lookup_regex);
	declare_function("uses_permission", "s", "i", usesPermission_lookup_string);

	declare_integer("new_permissions_number");
	declare_function("new_permission", "r", "i", newPermission_lookup_regex);
	declare_function("new_permission", "s", "i", newPermission_lookup_string);

	// From entries
	//declare_string("app_name");
	declare_function("app_name", "r", "i", appname_lookup_regex);
	declare_function("app_name", "s", "i", appname_lookup_string);

	//declare_string("displayed_version");
	declare_function("displayed_version", "r", "i", displayed_version_lookup_regex);
	declare_function("displayed_version", "s", "i", displayed_version_lookup_string);

	//declare_string("package_name");
	declare_function("package_name", "r", "i", package_name_lookup_regex);
	declare_function("package_name", "s", "i", package_name_lookup_string);

	// From lists
	declare_function("activity", "r", "i", activity_lookup_regex);
	declare_function("activity", "s", "i", activity_lookup_string);

	declare_function("filter", "r", "i", filter_lookup_regex);
	declare_function("filter", "s", "i", filter_lookup_string);

	declare_function("main_activity", "r", "i", main_activity_lookup_regex);
	declare_function("main_activity", "s", "i", main_activity_lookup_string);

	declare_function("receiver", "r", "i", receiver_lookup_regex);
	declare_function("receiver", "s", "i", receiver_lookup_string);

	declare_function("service", "r", "i", service_lookup_regex);
	declare_function("service", "s", "i", service_lookup_string);

	declare_function("url", "r", "i", url_lookup_regex);
	declare_function("url", "s", "i", url_lookup_string);

end_declarations;
#pragma endregion // ModuleDeclaration

int module_initialize(YR_MODULE* module)
{
	return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
	return ERROR_SUCCESS;
}

int module_load(YR_SCAN_CONTEXT* context, YR_OBJECT* module_object, void* module_data, size_t module_data_size)
{
	if (!module_data) {
		return ERROR_SUCCESS;
	}

	json_t* json;
	json_error_t json_error;
	json = json_loadb((const char*) module_data, module_data_size, JSON_ALLOW_NUL, &json_error);
	if (!json) {
		return ERROR_INVALID_MODULE_DATA;
	}

	//// Versions
	int32_t minSdkVer = json_integer_value(json_object_get(json, "min_sdk_version"));
	yr_set_integer(minSdkVer, module_object, "min_sdk");

	int32_t maxSdkVer = json_integer_value(json_object_get(json, "max_sdk_version"));
	yr_set_integer(maxSdkVer, module_object, "max_sdk");

	int32_t targetSdkVersion = json_integer_value(json_object_get(json, "target_sdk_version"));
	yr_set_integer(targetSdkVersion, module_object, "target_sdk");

	//// Certificates
	YR_OBJECT* certificate_obj = yr_get_object(module_object, "certificate");
	certificate_obj->data = json_object_get(json, "certificates");

	//// Permissions
	// Uses Permissions (from <uses-permission>)
	YR_OBJECT* usesPermission_obj = yr_get_object(module_object, "uses_permission");
	usesPermission_obj->data = (void*)json_object_get(json, "permissions_uses");
	int usesPermissionsNumber = json_array_size(usesPermission_obj->data);
	yr_set_integer(usesPermissionsNumber, module_object, "uses_permissions_number");

	// New permissions (from <permission>)
	YR_OBJECT* newPermission_obj = yr_get_object(module_object, "new_permission");
	newPermission_obj->data = (void*)json_object_get(json, "permissions_new");
	int newPermissionsNumber = json_array_size(newPermission_obj->data);
	yr_set_integer(newPermissionsNumber, module_object, "new_permissions_number");

	// Total permissions number
	yr_set_integer(usesPermissionsNumber + newPermissionsNumber, module_object, "permissions_number");

	//// From entries
	// Application name
	//const char* appName = (char*)json_string_value(json_object_get(json, "app_name"));
	YR_OBJECT* appName_obj = yr_get_object(module_object, "app_name");
	appName_obj->data = json_object_get(json, "app_name");

	// Displayed versions
	//const char* displayedVersion = (char*)json_string_value(json_object_get(json, "displayed_version"));
	YR_OBJECT* displayedVersion_obj = yr_get_object(module_object, "displayed_version");
	displayedVersion_obj->data = json_object_get(json, "displayed_version");

	// Package name
	//const char* packageName = (char*)json_string_value(json_object_get(json, "package_name"));
	YR_OBJECT* packageName_obj = yr_get_object(module_object, "package_name");
	packageName_obj->data = json_object_get(json, "package_name");

	//// From lists
	YR_OBJECT* activity_obj = yr_get_object(module_object, "activity");
	activity_obj->data = json_object_get(json, "activities");

	YR_OBJECT* filter_obj = yr_get_object(module_object, "filter");
	filter_obj->data = json_object_get(json, "filters");

	YR_OBJECT* mainActivity_obj = yr_get_object(module_object, "main_activity");
	mainActivity_obj->data = json_object_get(json, "main_activities");

	YR_OBJECT* receiver_obj = yr_get_object(module_object, "receiver");
	receiver_obj->data = json_object_get(json, "receivers");

	YR_OBJECT* service_obj = yr_get_object(module_object, "service");
	service_obj->data = json_object_get(json, "services");

	YR_OBJECT* url_obj = yr_get_object(module_object, "url");
	url_obj->data = json_object_get(json, "urls");

	return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
	if (module->data != NULL) {
		json_decref((json_t*)module->data);
	}
	return ERROR_SUCCESS;
}
