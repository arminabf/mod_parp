```
 ____  _____  ____ ____  
 |H _ \(____ |/ ___)  _ \ 
 |T|_| / ___ | |   | |_| |
 |T __/\_____|_|   |  __/ 
 |P|ParameterParser|_|    
```

mod_parp is a HTTP request parameter parser module for the Apache web server. It processes the request message body as well as the query portion of the request URL. The module parsed this data and provides all parameter to other Apache modules by a table of name/value pairs.

The following content types are supported:

- application/x-www-form-urlencoded
- multipart/form-data
- multipart/mixed

# Activation
The module is activated by setting the _parp_ key in either the request notes table (_r->notes_) or in the environment variables table (_r->subprocess_env_). mod_parp probes for the _parp_ variable at the header parser hook right after the Apache module mod_setenvif. You may set _parp_ by your own module or by using [mod_setenvif](https://httpd.apache.org/docs/current/mod/mod_setenvif.html).

```
# Load the module into your server:
LoadModule parp_module   <path to module>/mod_parp.so

# activate mod_parp for all requests matching the URL /a /b but not the URL /a/upload:
SetEnvIf   Request_URI   ^/a.*            parp
SetEnvIf   Request_URI   ^/a/upload.*    !parp
SetEnvIf   Request_URI   ^/b.*            parp

# suppress content types not supported by mod_parp:
SetEnvIf   Content-Type  text/plain      !parp
SetEnvIf   Content-Type  text/xml        !parp
SetEnvIf   Content-Type  text/html       !parp
```

# Error handling
mod_parp denies request on parsing errors by default. The default return code is 500. You may override this return code using the directive _PARP_ExitOnError &lt;code&gt;_. Set the code to 200 in order to ignore errors.

```
# Ignore parser errors
PARP_ExitOnError         200
```

# Memory
mod_parp stores the whole request message body in the servers memory. Use the _LimitRequestBody_ directive to limit the maximum data size.
You may use mod_deflate in order to decompress incomming data. mod_parp calulates the new Content-Length (total number of bytes) and stores it within the _PARPContentLength_ Apache environment variable.

# API
The table storing the request data my be accessed using an optional function or by registering a callback (hook) to mod_parp. Optional function sample code:

```
// (1) You may use the following forward declaration if not including mod_parp.h.
APR_DECLARE_OPTIONAL_FN(apr_table_t *, parp_hp_table, (request_rec *));

// (2) Implement your handler using the parp_hp_table() function. Don't call
//     the function before mod_parp's header parser has been executed.
static int parp_appl_handler(request_rec * r) {
  ...
  APR_OPTIONAL_FN_TYPE(parp_hp_table) *parp_appl_hp_table = 
    APR_RETRIEVE_OPTIONAL_FN(parp_hp_table);
  apt_table_t *tl = parp_appl_hp_table(r);
  if(tl) {
    int i;
    apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(tl)->elts;
    for(i = 0; i < apr_table_elts(tl)->nelts; ++i) {
      ap_rprintf(r, "%d: %s = %s\n", i,
                 ap_escape_html(r->pool, e[i].key),
                 ap_escape_html(r->pool, e[i].val));
      }
    }
  ...
```

Sample code using the mod_parp hook:

```
// (1) Include file providing the hook definitions
#include "mod_parp.h"

// (2) Implement the callback function processing the parameter table
//     Note: return DECLINED on success
static apr_status_t parp_appl_impl(request_rec *r, apr_table_t *table) {
  int i;
  apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(tl)->elts;
  for (i = 0; i < apr_table_elts(tl)->nelts; ++i) {
  ...
  return DECLINED;
}

// (3) Register your method to mod_parp
APR_OPTIONAL_HOOK(parp, hp_hook, parp_appl_impl, NULL, NULL, APR_HOOK_MIDDLE);
```

# Raw body processing:
mod_parp implements a function to access the raw body data of a HTTP POST request. Specify the raw content type handler using the _PARP_BodyData &lt;type&gt;" directive.

```
# Enable processing of other "raw" data types
PARP_BodyData text/plain text/xml text/html
SetEnvIf Content-Type  text/plain  parp
SetEnvIf Content-Type  text/xml    parp
SetEnvIf Content-Type  text/html   parp
```

You may enable raw body processing for any content type using "*/*" for its type. Sample code to access the raw body data:

```
// (1) You may use the following forward declaration if not including mod_parp.h 
APR_DECLARE_OPTIONAL_FN(char *, parp_body_data, (request_rec *, apr_size_t *));

// (2) Implement your handler using the parp_body_data() function. Don't call
//     the function before mod_parp's header parser has been executed.
static int parp_appl_handler(request_rec * r) {
  ...
  apr_size_t len;
  APR_OPTIONAL_FN_TYPE(parp_body_data) *parp_appl_body_data = 
    APR_RETRIEVE_OPTIONAL_FN(parp_body_data);
  const char *data = parp_appl_body_data(r, &len);
  if(data) {
  ...
```

# Parameter modification
mod_parp allows to modify query and body parameters. With the parp modify_hook an array is passed where the values can be modified or deleted. The array contains elements with the following structure:

```
parp_entry_t:
  key (string):       parameter name
  value (string):     original parameter value
  new_value (string): the modified value or NULL, to delete only the value set to "" (empty string)
  delete (integer):   if set != 0 the whole key/value pair is removed form the request
```

Sample code to modify the parameters is available in the following file: mod_parp_appl.c.

You may also remove parameters from the request by adding the name of the parameter to remove to the request notes variable _PARP_DELETE_PARAM_. For example like following:

```
apr_table_add(r->notes, "PARP_DELETE_PARAM", "special");
```
