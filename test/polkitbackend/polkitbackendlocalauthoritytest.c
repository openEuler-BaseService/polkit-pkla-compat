/*
 * Copyright (C) 2011 Google Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Nikki VonHollen <vonhollen@google.com>
 */

#include "config.h"
#include "glib.h"

#include <string.h>

#include <polkittesthelper.h>
#include <polkit/polkit.h>
#include <polkitbackend/polkitbackendlocalauthority.h>

#define BUILD_UTILITIES_DIR "../../src/polkitbackend"
#define PKLA_ADMIN_IDENTITIES_PATH BUILD_UTILITIES_DIR "/pkla-admin-identities"
#define TEST_CONFIG_PATH "etc/polkit-1/localauthority.conf.d"
#define TEST_AUTH_PATH1 "etc/polkit-1/localauthority"
#define TEST_AUTH_PATH2 "var/lib/polkit-1/localauthority"

/* Test helper types */

struct auth_context {
  const gchar *identity;
  gboolean subject_is_local;
  gboolean subject_is_active;
  const gchar *action_id;
  PolkitImplicitAuthorization implicit;
  PolkitImplicitAuthorization expect;
};

static PolkitBackendLocalAuthority *create_authority (void);


/* Test implementations */

static void
test_check_authorization_sync (const void *_ctx)
{
  const struct auth_context *ctx = (const struct auth_context *) _ctx;

  PolkitBackendLocalAuthority *authority = create_authority ();

  PolkitSubject *caller = polkit_unix_session_new ("caller-session");
  g_assert (caller);

  PolkitSubject *subject = polkit_unix_session_new ("subject-session");;
  g_assert (subject);

  GError *error = NULL;
  PolkitIdentity *user_for_subject = polkit_identity_from_string (ctx->identity, &error);
  g_assert_no_error (error);
  g_assert (user_for_subject);

  PolkitDetails *details = polkit_details_new ();
  g_assert (details);

  PolkitImplicitAuthorization auth;

  auth = polkit_backend_interactive_authority_check_authorization_sync (
      POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority),
      caller,
      subject,
      user_for_subject,
      ctx->subject_is_local,
      ctx->subject_is_active,
      ctx->action_id,
      details,
      ctx->implicit);

  g_assert_cmpint (auth, ==, ctx->expect);

  g_object_unref (authority);
  g_object_unref (caller);
  g_object_unref (subject);
  g_object_unref (user_for_subject);
  g_object_unref (details);
}

static void
test_get_admin_identities (void)
{
  gchar *config_path, *argv[4], *stdout_, *stderr_;
  gint status;
  GError *error;
  gboolean ok;

  config_path = polkit_test_get_data_path (TEST_CONFIG_PATH);

  /* Get the list of PolkitUnixUser objects who are admins */
  error = NULL;
  argv[0] = PKLA_ADMIN_IDENTITIES_PATH;
  argv[1] = "-c";
  argv[2] = config_path;
  argv[3] = NULL;
  ok = g_spawn_sync (".", argv, NULL, 0, NULL, NULL, &stdout_, &stderr_, &status,
		     &error);
  g_assert_no_error (error);
  g_assert (ok);

  ok = g_spawn_check_exit_status (status, &error);
  g_assert_no_error (error);
  g_assert (ok);

  g_assert_cmpstr (stderr_, ==, "");

  /* Drop last '\n' so that g_strsplit doesn't add an empty string */
  gchar *stdout_end = strchr (stdout_, '\0');
  if (stdout_end > stdout_ && stdout_end[-1] == '\n')
    stdout_end[-1] = '\0';

  gchar **result = g_strsplit (stdout_, "\n", 0);

  guint result_len = g_strv_length (result);
  g_assert_cmpint (result_len, >, 0);

  /* Test against each of the admins in the following list */
  const gchar *expect_admins [] = {
    "unix-user:root",
    "unix-netgroup:bar",
    "unix-group:admin",
    NULL,
  };

  unsigned int i;
  for (i = 0; expect_admins[i] != NULL; i++)
  {
    g_assert_cmpint (i, <, result_len);

    PolkitIdentity *test_identity = polkit_identity_from_string (result[i],
								 &error);
    g_assert_no_error (error);
    g_assert (test_identity);

    gchar *test_identity_str = polkit_identity_to_string (test_identity);
    g_assert_cmpstr (expect_admins[i], ==, test_identity_str);

    g_free (test_identity_str);
    g_object_unref (test_identity);
  }
  g_assert (result[i] == NULL);

  g_strfreev (result);
  g_free (stdout_);
  g_free (stderr_);
  g_free (config_path);
}


/* Factory for mock local authority. */
static PolkitBackendLocalAuthority *
create_authority (void)
{
  gchar *config_path = polkit_test_get_data_path (TEST_CONFIG_PATH);
  gchar *auth_path1 = polkit_test_get_data_path (TEST_AUTH_PATH1);
  gchar *auth_path2 = polkit_test_get_data_path (TEST_AUTH_PATH2);
  gchar *auth_paths = g_strconcat (auth_path1, ";", auth_path2, NULL);

  g_assert (config_path);
  g_assert (auth_path1);
  g_assert (auth_path2);
  g_assert (auth_paths);
  
  PolkitBackendLocalAuthority *authority = g_object_new (
      POLKIT_BACKEND_TYPE_LOCAL_AUTHORITY,
      "config-path", config_path,
      "auth-store-paths", auth_paths,
      NULL);
  
  g_free (config_path);
  g_free (auth_path1);
  g_free (auth_path2);
  g_free (auth_paths);
  return authority;
}


/* Variations of the check_authorization_sync */
struct auth_context check_authorization_test_data [] = {
  /* Test root, john, and jane on action awesomeproduct.foo (all users are ok) */
  {"unix-user:root", TRUE, TRUE, "com.example.awesomeproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED},
  {"unix-user:root", TRUE, FALSE, "com.example.awesomeproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED},
  {"unix-user:root", FALSE, FALSE, "com.example.awesomeproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED},
  {"unix-user:john", TRUE, TRUE, "com.example.awesomeproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED},
  {"unix-user:jane", TRUE, TRUE, "com.example.awesomeproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED},

  /* Test root, john, and jane on action restrictedproduct.foo (only root is ok) */
  {"unix-user:root", TRUE, TRUE, "com.example.restrictedproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED},
  {"unix-user:john", TRUE, TRUE, "com.example.restrictedproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN},
  {"unix-user:jane", TRUE, TRUE, "com.example.restrictedproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN},

  /* Test root against some missing actions */
  {"unix-user:root", TRUE, TRUE, "com.example.missingproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN},

  /* Test root, john, and jane against action awesomeproduct.bar
   * which uses "unix-netgroup:baz" for auth (john and jane are OK, root is not) */
  {"unix-user:root", TRUE, TRUE, "com.example.awesomeproduct.bar",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN},
  {"unix-user:john", TRUE, TRUE, "com.example.awesomeproduct.bar",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED},
  {"unix-user:jane", TRUE, TRUE, "com.example.awesomeproduct.bar",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED},

  /* Test user/group/default handling */
  {"unix-user:john", TRUE, TRUE, "com.example.awesomeproduct.defaults-test",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED},
  {"unix-user:sally", TRUE, TRUE, "com.example.awesomeproduct.defaults-test",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED},
  {"unix-user:jane", TRUE, TRUE, "com.example.awesomeproduct.defaults-test",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED},

  {NULL},
};


/* Automatically create many variations of the check_authorization_sync test */
static void
add_check_authorization_tests (void) {
  unsigned int i;
  for (i = 0; check_authorization_test_data[i].identity; i++) {
    struct auth_context *ctx = &check_authorization_test_data[i];
    gchar *test_name = g_strdup_printf (
        "/PolkitBackendLocalAuthority/check_authorization_sync_%d", i);
    g_test_add_data_func (test_name, ctx, test_check_authorization_sync);
    g_free (test_name);
  }
};


int
main (int argc, char *argv[])
{
  g_type_init ();
  g_test_init (&argc, &argv, NULL);
  polkit_test_redirect_logs ();

  add_check_authorization_tests ();
  g_test_add_func ("/PolkitBackendLocalAuthority/get_admin_identities", test_get_admin_identities);

  return g_test_run ();
};
