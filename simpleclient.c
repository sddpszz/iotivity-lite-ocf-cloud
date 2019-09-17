/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "oc_api.h"
#include "oc_uuid.h"
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include "oc_collection.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

pthread_mutex_t mutex;
pthread_cond_t cv;

pthread_mutex_t user_mutex;
pthread_cond_t user_cv;

pthread_mutex_t lock_mutex;


void down()
{
	pthread_mutex_lock(&user_mutex);
	pthread_cond_wait(&user_cv,&user_mutex);
	pthread_mutex_unlock(&user_mutex);
}

void up()
{
	pthread_mutex_lock(&user_mutex);
	pthread_cond_signal(&user_cv);
	pthread_mutex_unlock(&user_mutex);
}

void lock()
{
	pthread_mutex_lock(&lock_mutex);
}

void unlock()
{
	pthread_mutex_unlock(&lock_mutex);
}


struct timespec ts;

int quit = 0;

static int
app_init(void)
{
  int ret = oc_init_platform("Apple", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

oc_endpoint_t s_cloudEndpoint;

/** Account URI.*/
#define ACCOUNT_URI "/oic/account"

/** Account session URI.*/
#define ACCOUNT_SESSION_URI "/oic/account/session"

/** RD.*/
#define RD_URI "/oic/rd"


#define MAX_UUID_LENGTH 37
char *s_authcode = NULL;

oc_string_t uid;
oc_string_t access_token;

oc_resource_t *s_pResource1 = NULL;
oc_resource_t *s_pResource2 = NULL;



bool s_lightState = false;

bool ocSignInWithAuth();
bool rd_publish(oc_endpoint_t *endpoint, oc_link_t *links, int device_index,oc_response_handler_t handler, oc_qos_t qos, void *user_data);
bool rd_publish_all(oc_endpoint_t *endpoint, int device_index,oc_response_handler_t handler, oc_qos_t qos, void *user_data);

static bool
_oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
            const char *auth_code, const char *uid, const char *access_token, 
            int device_index, oc_response_handler_t handler, void *user_data)
{
  if (!endpoint || ((!auth_provider || !auth_code) && !access_token) ||
      !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  if (oc_init_post(ACCOUNT_URI, endpoint, NULL, handler, LOW_QOS,
                   user_data)) {
    char uuid[MAX_UUID_LENGTH] = { 0 };
    oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, MAX_UUID_LENGTH);
    
    oc_rep_start_root_object();

	OC_DBG("di =%s ,uuid = %s \n",oc_core_get_device_id(device_index),uuid);
    oc_rep_set_text_string(root, di, uuid);
    if (auth_provider)
      oc_rep_set_text_string(root, authprovider, auth_provider);
    if (auth_code) {
      oc_rep_set_text_string(root, authcode, auth_code);
    } else {
      if (uid)
        oc_rep_set_text_string(root, uid, uid);
      oc_rep_set_text_string(root, accesstoken, access_token);
    }
    
    oc_rep_set_text_string(root, devicetype, "device");
    oc_rep_end_root_object();
  } else {
    OC_ERR("Could not init POST request for sign up");
    return false;
  }

  return oc_do_post();
}



bool
oc_sign_up_with_auth(oc_endpoint_t *endpoint, const char *auth_provider,
                     const char *auth_code, int device_index,
                     oc_response_handler_t handler, void *user_data)
{
  return _oc_sign_up(endpoint, auth_provider, auth_code, NULL, NULL,
                     device_index, handler, user_data);
}

static void parsePayload(oc_client_response_t *data) {
	oc_rep_t *rep = data->payload;
	while (rep != NULL) {
		printf("key %s, value ", oc_string(rep->name));
		switch (rep->type) {
		case OC_REP_BOOL:
			printf("%d\n", rep->value.boolean);
			break;
		case OC_REP_INT:
			printf("%d\n", rep->value.integer);
			break;
		case OC_REP_STRING:
			printf("%s\n", oc_string(rep->value.string));
			if (strncmp("uid", oc_string(rep->name), oc_string_len(rep->name))
					== 0) {
				if (oc_string_len(uid))
					oc_free_string(&uid);
				oc_new_string(&uid, oc_string(rep->value.string),
						oc_string_len(rep->value.string));
			} else if (strncmp("accesstoken", oc_string(rep->name),
					oc_string_len(rep->name)) == 0) {
				if (oc_string_len(access_token))
					oc_free_string(&access_token);
				oc_new_string(&access_token, oc_string(rep->value.string),
						oc_string_len(rep->value.string));
			}
			break;
		default:
			printf("NULL\n");
			break;
		}
		rep = rep->next;
	}
}


static void cloudPostResponseCb(oc_client_response_t *data) {
	if (data->code == OC_STATUS_CHANGED)
		printf("POST response: CHANGED\n");
	else if (data->code == OC_STATUS_CREATED)
		printf("POST response: CREATED\n");
	else
		printf("POST response code %d\n", data->code);

	parsePayload(data);
	up();
}


void rdResponseCb(oc_client_response_t *data){
	if (data->code == OC_STATUS_CHANGED)
		printf("POST response: CHANGED\n");
	else if (data->code == OC_STATUS_CREATED)
		printf("POST response: CREATED\n");
	else
		printf("POST response code %d\n", data->code);

	parsePayload(data);

}

void getLightCb(oc_request_t *request,
		oc_interface_mask_t interface, void *user_data) {
	PRINT("getLightCb:\n");
	(void) user_data;
	oc_rep_start_root_object();
	switch (interface) {
	case OC_IF_BASELINE:
		oc_process_baseline_interface(request->resource);
		/* fall through */
	case OC_IF_RW:
		oc_rep_set_boolean(root, state, s_lightState);
		break;
	default:
		break;
	}
	oc_rep_end_root_object();
	oc_send_response(request, OC_STATUS_OK);
	PRINT("Light state %d\n", s_lightState);
}

void setLightCb(oc_request_t *request,
		oc_interface_mask_t interface, void *user_data) {
	PRINT("setLightCb:\n");
	(void) user_data;
	oc_rep_start_root_object();
	switch (interface) {
	case OC_IF_BASELINE:
		oc_process_baseline_interface(request->resource);
		/* fall through */
	case OC_IF_RW:
		
		oc_rep_set_boolean(root, state, s_lightState);
		break;
	default:
		break;
	}
	s_lightState = (s_lightState == false) ? true :false ;
	oc_rep_set_boolean(root, state, s_lightState);
	oc_rep_end_root_object();
	oc_send_response(request, OC_STATUS_OK);
	PRINT("Light state %d\n", s_lightState);
}


static void cloudsignInResponseCb(oc_client_response_t *data) {
	if (data->code == OC_STATUS_CHANGED)
		printf("POST response: CHANGED\n");
	else if (data->code == OC_STATUS_CREATED)
		printf("POST response: CREATED\n");
	else
		printf("POST response code %d\n", data->code);

	parsePayload(data);
	up();	
}



bool ocSignUpWithAuth(const char *provier, const char *address,
		const char *auth_code,oc_response_handler_t handler) {


	if (strlen(address) != 0) {
		oc_string_t address_str;
		oc_new_string(&address_str, address, strlen(address));

		oc_string_to_endpoint(&address_str, &s_cloudEndpoint, NULL);
		oc_free_string(&address_str);

	}

	return oc_sign_up_with_auth(&s_cloudEndpoint, provier, auth_code, 0,handler,NULL);
}

static bool
oc_sign_inout(oc_endpoint_t *endpoint, const char *uid,
              const char *access_token,  int device_index, bool is_sign_in,
              oc_response_handler_t handler, void *user_data)
{
  if (!endpoint || (is_sign_in && !uid) || !access_token || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  if (oc_init_post(ACCOUNT_SESSION_URI, endpoint, NULL, handler,
                   LOW_QOS, user_data)) {
    char uuid[MAX_UUID_LENGTH] = { 0 };
    oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, MAX_UUID_LENGTH);
	OC_DBG("di =%s ,uuid = %s \n",oc_core_get_device_id(device_index),uuid);
    oc_rep_start_root_object();
    if (is_sign_in)
      oc_rep_set_text_string(root, uid, uid);
    oc_rep_set_text_string(root, di, uuid);
    oc_rep_set_text_string(root, accesstoken, access_token);
    oc_rep_set_boolean(root, login, is_sign_in);
    oc_rep_end_root_object();
  } else {
    OC_ERR("Could not init POST request for sign in/out");
    return false;
  }

  return oc_do_post();
}



bool
oc_sign_in(oc_endpoint_t *endpoint, const char *uid, const char *access_token,
           int device_index, oc_response_handler_t handler, void *user_data)
{
  return oc_sign_inout(endpoint, uid, access_token, device_index, true, handler,
                       user_data);
}


bool ocSignInWithAuth() {
	
	return oc_sign_in(&s_cloudEndpoint, oc_string(uid), oc_string(access_token),
			0, cloudsignInResponseCb, NULL);
}

void registerResources(void) {
	PRINT("registerResourcesCb\n");

	s_pResource1 = oc_new_resource(NULL, "/power/0", 1, 0);
	oc_resource_bind_resource_type(s_pResource1, "oic.r.switch.binary");
	oc_resource_bind_resource_interface(s_pResource1, OC_IF_RW);
	oc_resource_set_default_interface(s_pResource1, OC_IF_BASELINE);
	oc_resource_set_discoverable(s_pResource1, true);
	oc_resource_set_request_handler(s_pResource1, OC_GET, getLightCb, NULL);
	oc_resource_set_request_handler(s_pResource1, OC_POST, setLightCb, NULL);
	oc_add_resource(s_pResource1);

	s_pResource2 = oc_new_resource(NULL, "/power/1", 1, 0);
	oc_resource_bind_resource_type(s_pResource2, "oic.r.switch.binary");
	oc_resource_bind_resource_interface(s_pResource2, OC_IF_RW);
	oc_resource_set_default_interface(s_pResource2, OC_IF_BASELINE);
	oc_resource_set_discoverable(s_pResource2, true);
	oc_resource_set_request_handler(s_pResource2, OC_GET, getLightCb, NULL);
	oc_resource_set_request_handler(s_pResource2, OC_POST, setLightCb, NULL);
	oc_add_resource(s_pResource2);

}


void
_add_resource_payload(CborEncoder *parent, oc_resource_t *resource, char *rel,
                      char *ins)
{
  if (!parent || !resource) {
    OC_ERR("Error of input parameters");
    return;
  }
  oc_rep_start_object(parent, links);
  oc_rep_set_text_string(links, href, oc_string(resource->uri));
  oc_rep_set_string_array(links, rt, resource->types);
  oc_core_encode_interfaces_mask(oc_rep_object(links), resource->interfaces);
  if (rel)
    oc_rep_set_text_string(links, rel, rel);
  int ins_int = 0;
  if (ins)
    ins_int = atoi(ins);
  oc_rep_set_int(links, ins, ins_int);
  oc_rep_set_object(links, p);
  oc_rep_set_uint(p, bm,(uint8_t)(resource->properties & ~(OC_PERIODIC | OC_SECURE)));
  oc_rep_close_object(links, p);
  oc_rep_end_object(parent, links);
}



bool
rd_publish_with_device_id(oc_endpoint_t *endpoint, struct oc_link_s *links,
                          const char *id, const char *name,
                          oc_response_handler_t handler, oc_qos_t qos,
                          void *user_data)
{
  if (!endpoint || !id || !links || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  if (oc_init_post(RD_URI, endpoint, "rt=oic.wk.rdpub", handler, qos,
                   user_data)) {

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, di, id);
    oc_rep_set_text_string(root, n, name);
    oc_rep_set_int(root, lt, 86400);

    oc_rep_set_array(root, links);
    struct oc_link_s *link = links;
    while (link != NULL) {
      _add_resource_payload(oc_rep_array(links), link->resource,
                            oc_string_array_get_item(link->rel, 0),
                            oc_string(link->ins));
      link = link->next;
    }
    oc_rep_close_array(root, links);
    oc_rep_end_root_object();
  } else {
    OC_ERR("Could not init POST request for rd publish");
    return false;
  }

  return oc_do_post();
}


bool
rd_publish(oc_endpoint_t *endpoint, oc_link_t *links, int device_index,
           oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  char uuid[MAX_UUID_LENGTH] = { 0 };
  oc_device_info_t *device_info = oc_core_get_device_info(device_index);
  if (!device_info)
    return false;
  oc_uuid_to_str(&device_info->di, uuid, MAX_UUID_LENGTH);

  bool status = false;

  status = rd_publish_with_device_id(endpoint, links, uuid,
                                       oc_string(device_info->name), handler,
                                       qos, user_data);
  return status;
}


bool
rd_publish_all(oc_endpoint_t *endpoint, int device_index,
               oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  if (!endpoint || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  if (oc_init_post(RD_URI, endpoint, "rt=oic.wk.rdpub", handler, qos,
                   user_data)) {
    char uuid[MAX_UUID_LENGTH] = { 0 };
    oc_device_info_t *device_info = oc_core_get_device_info(device_index);
    if (!device_info)
      return false;
    oc_uuid_to_str(&device_info->di, uuid, MAX_UUID_LENGTH);

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, di, uuid);
    oc_rep_set_text_string(root, n, oc_string(device_info->name));
    oc_rep_set_int(root, lt, 86400);

    oc_rep_set_array(root, links);
    _add_resource_payload(oc_rep_array(links),
                          oc_core_get_resource_by_index(OCF_P, device_index),
                          NULL, NULL);
    _add_resource_payload(oc_rep_array(links),
                          oc_core_get_resource_by_index(OCF_D, device_index),
                          NULL, NULL);
    oc_resource_t *resource = oc_ri_get_app_resources();
    for (; resource; resource = resource->next) {
      if (resource->device != (size_t)device_index ||
          !(resource->properties & OC_DISCOVERABLE))
        continue;
      _add_resource_payload(oc_rep_array(links), resource, NULL, NULL);
    }
    oc_rep_close_array(root, links);
    oc_rep_end_root_object();
  } else {
    OC_ERR("Could not init POST request for rd publish all");
    return false;
  }

  return oc_do_post();
}


void nofityObserver(const char * uri)
{
	lock();
	oc_resource_t *res = oc_ri_get_app_resource_by_uri(uri, strlen(uri), 0);
	oc_notify_observers(res);
	unlock();
	_oc_signal_event_loop();
}


static void* user_function_thread()
{
//register local resource .
	registerResources();
//sign up
  	ocSignUpWithAuth("github","coaps+tcp://2cq5762044.qicp.vip:49208",s_authcode,cloudPostResponseCb); 
  	down();
	ocSignInWithAuth();
	down();
//	we assume to publish 2 device 
	rd_publish_all(&s_cloudEndpoint,0,rdResponseCb,LOW_QOS,NULL);
//	rd_publish_all(&s_cloudEndpoint,1,rdResponseCb,LOW_QOS,NULL);

	char Q;
	while(1){
		scanf("%s",&Q);
		if(Q == 'q'){
			nofityObserver("/power/0");
		}
	}
	
  	return NULL;
}

static void
issue_requests(void)
{
	pthread_t ntid;
 	int err = pthread_create(&ntid,NULL,user_function_thread,NULL);
	if(err != 0){
		OC_ERR("Could not create user thread !");
	}
}

int
main(int argc,char **argv)
{

  if(argc < 1){

  }
  s_authcode = argv[1];
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = issue_requests };

  oc_clock_time_t next_event;

#ifdef OC_SECURITY
  oc_storage_config("./simpleclient_creds");
#endif               /* OC_SECURITY */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;
  
  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
  oc_main_shutdown();
  return 0;
}
