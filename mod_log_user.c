/*
 * mod_log_user - Username logging module for apache httpd 2.0/2.2
 *
 * Compile & install with : apxs2 -i -a -c mod_log_user.c
 *
 * This very tiny module fills the r->user field with username so that
 * it is available for logging.
 *
 * If there is an Authentication header, gets username so that it is available
 * for logging even if there is no Authentication module involved. Works with
 * Basic and Digest authentication.
 *
 * This module can be useful in a reverse proxy environment where the proxy
 * logs all the traffic and authentication is done by proxyfied servers but
 * you want to log usernames in the main proxy logfile.
 *
 * There is no configuration parameter, no activation switch, just load
 * the module and it will silently do its work.
 *
 * Author  : Jérôme Grandjanny ( jerome.grandjanny@laposte.net )
 * Date    : April, 23th 2011
 * Version : 1.0
 *
 * Licensed under the : http://www.apache.org/licenses/LICENSE-2.0
 */
#include <apr_lib.h>
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

static apr_status_t do_log_user ( request_rec *r )
{
    const char *auth_line;
    const char *auth_scheme;
    const char *user;
    char *decoded_line;
    int length;

    ap_log_rerror ( APLOG_MARK, APLOG_DEBUG, 0, r, "Entering do_log_user function." ) ;

    /* Test if there is an Authorization header */
    auth_line = apr_table_get(r->headers_in, "Authorization");
    if (!auth_line) {
        return DECLINED ;
    }

    ap_log_rerror ( APLOG_MARK, APLOG_DEBUG, 0, r, "Found autentication header : %s", auth_line ) ;

    auth_scheme = ap_getword(r->pool, &auth_line, ' ') ;

    ap_log_rerror ( APLOG_MARK, APLOG_DEBUG, 0, r, "Autentication scheme = \"%s\"", auth_scheme ) ;

    /* Skip leading spaces. */
    while (apr_isspace(*auth_line)) {
        auth_line++;
    }

    if (!strcasecmp(auth_scheme, "Basic")) {

        decoded_line = apr_palloc(r->pool, apr_base64_decode_len(auth_line) + 1);
        length = apr_base64_decode(decoded_line, auth_line);
        /* Null-terminate the string. */
        decoded_line[length] = '\0';

        ap_log_rerror ( APLOG_MARK, APLOG_DEBUG, 0, r, "Autentication string = \"%s\"", decoded_line ) ;

        user = ap_getword_nulls(r->pool, (const char**)&decoded_line, ':');

        ap_log_rerror ( APLOG_MARK, APLOG_DEBUG, 0, r, "User = \"%s\"", user ) ;

        r->user = (char *) user;
    }

    if (!strcasecmp(auth_scheme, "Digest")) {
        auth_line = strcasestr ( auth_line, "username=\"" ) ;
        if (!auth_line) {
            return DECLINED ;
        }
        auth_line += 10 ;
        user = ap_getword(r->pool, &auth_line, '"') ;
        ap_log_rerror ( APLOG_MARK, APLOG_DEBUG, 0, r, "User = \"%s\"", user ) ;
        r->user = (char *) user;
    }
    
    return DECLINED;
}

static void mod_log_user_register_hooks(apr_pool_t *p)
{
  ap_hook_post_read_request ( do_log_user, NULL, NULL, APR_HOOK_MIDDLE );
}

module AP_MODULE_DECLARE_DATA log_user_module = 
  {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    mod_log_user_register_hooks
  };
