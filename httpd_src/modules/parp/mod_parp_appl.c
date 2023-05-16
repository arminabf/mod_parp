/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 * The line above sets XEmacs indention to offset 2,
 * and does not insert tabs
 */
/*  ____  _____  ____ ____  
 * |H _ \(____ |/ ___)  _ \ 
 * |T|_| / ___ | |   | |_| |
 * |T __/\_____|_|   |  __/ 
 * |P|ParameterParser|_|    
 * http://parp.sourceforge.net
 *
 * Copyright (C) 2008-2010 Christian Liesch/Pascal Buchbinder
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/************************************************************************
 * Version
 ***********************************************************************/
static const char revision[] = "$Id: mod_parp_appl.c,v 1.15 2012-09-26 06:11:26 pbuchbinder Exp $";
static const char g_revision[] = "0.1";

/************************************************************************
 * Includes
 ***********************************************************************/
/* apache */
#include <httpd.h>
#include <http_main.h>
#include <http_request.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>

/* apr */
#include <apr_hooks.h>
#include <apr_strings.h>

/* param parser module */
#include "mod_parp.h"

/************************************************************************
 * defines
 ***********************************************************************/
#define PARPA_LOG_PFX(id)  "mod_parp_appl("#id"): "

/************************************************************************
 * globals
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA parp_appl_module;
static int  m_disable_mod = 0;


/************************************************************************
 * functions
 ***********************************************************************/

/**
 * The parameter may be access via the optional function parp_hp_table()
 */
//static APR_OPTIONAL_FN_TYPE(parp_hp_table) *parp_appl_hp_table = NULL;

/**
 * This is the function which has been registered to mod_parp's header
 * parser. It receives a table with all parameter received from the client
 * (either body or query).
 */
static apr_status_t parp_appl_test(request_rec *r, apr_table_t *table) {
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                PARPA_LOG_PFX(000)"parp header parser hook implementation");
  ap_set_module_config(r->request_config, &parp_appl_module, table);
  return DECLINED;
}

static apr_status_t parp_appl_modify(request_rec *r, apr_array_header_t *array) {
  /* run for /htt/modify* only */
  if(strstr(r->uri, "/modify") != NULL) {
    int i;
    parp_entry_t *entries = (parp_entry_t *)array->elts;
    for(i = 0; i < array->nelts; ++i) {
      parp_entry_t *b = &entries[i];
      if(strcmp(b->value, "changeme") == 0) {
        /* longer */
        b->new_value = "this_has_changed";
      }
      if(strcmp(b->value, "changethat") == 0) {
        /* shorter */
        b->new_value = "here";
      }
      if(strcmp(b->value, "deletethis") == 0) {
        /* 0 bytes */
        b->new_value = "";
      }
      if(strcmp(b->value, "deleteparam") == 0) {
        b->delete = 1;
      }
    }
  }
  return DECLINED;
}

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * The test handler writes all parameter to the response body
 * in order to be verified the by the test program.
 * See also http://htt.sourceforge.net about smart web application
 * testing.
 */
static int parp_appl_handler(request_rec * r) {
  apr_table_t *tl = ap_get_module_config(r->request_config, &parp_appl_module);
  APR_OPTIONAL_FN_TYPE(parp_hp_table) *parp_appl_hp_table = NULL;
  APR_OPTIONAL_FN_TYPE(parp_body_data) *parp_appl_body_data = NULL;
  char *data;
  apr_size_t len;

  /* We decline to handle a request if parp-test-handler is not the value
   * of r->handler 
   */
  if (strcmp(r->handler, "parp-test-handler")) {
    return DECLINED;
  }

  /* We set the content type before doing anything else */
  ap_set_content_type(r, "text/plain");

  /* If the request is for a header only, and not a request for
   * the whole content, then return OK now. We don't have to do
   * anything else. 
   */
  if (r->header_only) {
    return OK;
  }

  if(tl) {
    int i;
    apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(tl)->elts;
    for (i = 0; i < apr_table_elts(tl)->nelts; ++i) {
      ap_rprintf(r, "recvd: %s = %s\n",
                 ap_escape_html(r->pool, e[i].key),
                 ap_escape_html(r->pool, e[i].val));
    }
  }

  /*
   * Access the parameter using the optional function
   */
  parp_appl_hp_table =  APR_RETRIEVE_OPTIONAL_FN(parp_hp_table);
  tl = parp_appl_hp_table(r);
  if(tl) {
    int i;
    apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(tl)->elts;
    for (i = 0; i < apr_table_elts(tl)->nelts; ++i) {
      ap_rprintf(r, "of: %s = %s\n",
                 ap_escape_html(r->pool, e[i].key),
                 ap_escape_html(r->pool, e[i].val));
    }
  }

  /*
   * Access the body data using the optional function
   */
  {
    const char *body;
    parp_appl_body_data =  APR_RETRIEVE_OPTIONAL_FN(parp_body_data);
    body = parp_appl_body_data(r, &len);
    data = apr_pstrndup(r->pool, body, len); // copy the data because we are modifying it
    if (data) {
      int i;
      data[len] = 0;
      for (i = 0; i < len; i++) {
        if (data[i] < 32 && data[i] != '\n' && data[i] != '\r') {
          data[i] = '.';
        }
      }
      ap_rprintf(r, "body: %s\n", ap_escape_html(r->pool, data));
    }
  }
  
  
  return OK;
}

/**
 * This module implements a handler which actiates mod_parp.
 * We could do this using mod_setenvif alternatively.
 */
static int parp_appl_post_read_request(request_rec * r) {
  if(ap_is_initial_req(r)) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  PARPA_LOG_PFX(000)"prr, enable parp");
    /*
     * should only be activated for content types known my mod_parp
     */
//    const char *ct = apr_table_get(r->headers_in, "Content-Type");
//    if(ct) {
//      if(ap_strcasestr(ct, "application/x-www-form-urlencoded") ||
//         ap_strcasestr(ct, "multipart/form-data") ||
//         ap_strcasestr(ct, "multipart/mixed")) {
        apr_table_set(r->subprocess_env, "parp", "on");
//      }
//    }

        // test if we can remove parameter
        apr_table_add(r->notes, "PARP_DELETE_PARAM", "alwaysremoveme");
  }
  return DECLINED;
}

static int parp_appl_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                                 apr_pool_t *ptemp, server_rec *bs) {
  if(!m_disable_mod) {
    APR_OPTIONAL_HOOK(parp, modify_hook, parp_appl_modify, NULL, NULL, APR_HOOK_MIDDLE);
  }
  return DECLINED;
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/
static void *parp_appl_srv_config_create(apr_pool_t *p, server_rec *s) {
  return NULL;
}

static void *parp_appl_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  return addv;
}

const char *parp_appl_disable_modify_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  m_disable_mod = flag;
  return NULL;
}

static const command_rec parp_appl_config_cmds[] = {
  AP_INIT_FLAG("DisableModifyBodyHook", parp_appl_disable_modify_cmd, NULL,
               RSRC_CONF,
               ""),
  { NULL }
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void parp_appl_register_hooks(apr_pool_t * p) {
  static const char *post[] = { "mod_setenvif.c", NULL };
  ap_hook_post_read_request(parp_appl_post_read_request, NULL, post, APR_HOOK_LAST);
  ap_hook_handler(parp_appl_handler, NULL, NULL, APR_HOOK_LAST);
  APR_OPTIONAL_HOOK(parp, hp_hook, parp_appl_test, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_config(parp_appl_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA parp_appl_module ={ 
  STANDARD20_MODULE_STUFF,
  NULL,                                     /**< dir config creater */
  NULL,                                     /**< dir merger */
  parp_appl_srv_config_create,              /**< server config */
  parp_appl_srv_config_merge,               /**< server merger */
  parp_appl_config_cmds,                    /**< command table */
  parp_appl_register_hooks,                 /**< hook registery */
};
