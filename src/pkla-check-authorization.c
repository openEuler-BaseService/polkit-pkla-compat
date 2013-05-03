/*
 * Copyright (C) 2008 Red Hat, Inc.
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
 * Author: David Zeuthen <davidz@redhat.com>
 */

#include "config.h"
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <glib/gstdio.h>
#include <locale.h>
#include <glib/gi18n.h>

#include <polkit/polkit.h>
#include "polkitbackendlocalauthorizationstore.h"

static GList *get_groups_for_user (PolkitIdentity              *user);

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  gchar **authorization_store_paths;
  GList *authorization_stores;

} PolkitBackendLocalAuthorityPrivate;

/* ---------------------------------------------------------------------------------------------------- */

static void
purge_all_authorization_stores (PolkitBackendLocalAuthorityPrivate *priv)
{
  GList *l;

  for (l = priv->authorization_stores; l != NULL; l = l->next)
    {
      PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (l->data);
      g_object_unref (store);
    }
  g_list_free (priv->authorization_stores);
  priv->authorization_stores = NULL;

  g_debug ("Purged all local authorization stores");
}

/* ---------------------------------------------------------------------------------------------------- */

static void
add_one_authorization_store (PolkitBackendLocalAuthorityPrivate *priv,
                             GFile                       *directory)
{
  PolkitBackendLocalAuthorizationStore *store;

  store = polkit_backend_local_authorization_store_new (directory, ".pkla");
  priv->authorization_stores = g_list_append (priv->authorization_stores, store);
}

static gint
authorization_store_path_compare_func (GFile *file_a,
                                       GFile *file_b)
{
  const gchar *a;
  const gchar *b;

  a = g_object_get_data (G_OBJECT (file_a), "sort-key");
  b = g_object_get_data (G_OBJECT (file_b), "sort-key");

  return g_strcmp0 (a, b);
}

static void
add_all_authorization_stores (PolkitBackendLocalAuthorityPrivate *priv)
{
  guint n;
  GList *directories;
  GList *l;

  directories = NULL;

  for (n = 0; priv->authorization_store_paths && priv->authorization_store_paths[n]; n++)
    {
      const gchar *toplevel_path;
      GFile *toplevel_directory;
      GFileEnumerator *directory_enumerator;
      GFileInfo *file_info;
      GError *error;

      error = NULL;

      toplevel_path = priv->authorization_store_paths[n];
      toplevel_directory = g_file_new_for_path (toplevel_path);
      directory_enumerator = g_file_enumerate_children (toplevel_directory,
                                                        "standard::name,standard::type",
                                                        G_FILE_QUERY_INFO_NONE,
                                                        NULL,
                                                        &error);
      if (directory_enumerator == NULL)
        {
          g_warning ("Error getting enumerator for %s: %s", toplevel_path, error->message);
          g_error_free (error);
          g_object_unref (toplevel_directory);
          continue;
        }

      while ((file_info = g_file_enumerator_next_file (directory_enumerator, NULL, &error)) != NULL)
        {
          /* only consider directories */
          if (g_file_info_get_file_type (file_info) == G_FILE_TYPE_DIRECTORY)
            {
              const gchar *name;
              GFile *directory;
              gchar *sort_key;

              name = g_file_info_get_name (file_info);

              /* This makes entries in directories in /etc take precedence to entries in directories in /var */
              sort_key = g_strdup_printf ("%s-%d", name, n);

              directory = g_file_get_child (toplevel_directory, name);
              g_object_set_data_full (G_OBJECT (directory), "sort-key", sort_key, g_free);

              directories = g_list_prepend (directories, directory);
            }
          g_object_unref (file_info);
        }
      if (error != NULL)
        {
          g_warning ("Error enumerating files in %s: %s", toplevel_path, error->message);
          g_error_free (error);
          g_object_unref (toplevel_directory);
          g_object_unref (directory_enumerator);
          continue;
        }
      g_object_unref (directory_enumerator);
      g_object_unref (toplevel_directory);
    }

  /* Sort directories */
  directories = g_list_sort (directories, (GCompareFunc) authorization_store_path_compare_func);

  /* And now add an authorization store for each one */
  for (l = directories; l != NULL; l = l->next)
    {
      GFile *directory = G_FILE (l->data);
      gchar *name;

      name = g_file_get_path (directory);
      g_debug ("Added `%s' as a local authorization store", name);
      g_free (name);

      add_one_authorization_store (priv, directory);
    }

  g_list_foreach (directories, (GFunc) g_object_unref, NULL);
  g_list_free (directories);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_init (PolkitBackendLocalAuthorityPrivate *priv)
{
  priv->authorization_store_paths = NULL;
}

static void
polkit_backend_local_authority_constructed (PolkitBackendLocalAuthorityPrivate *priv)
{
  add_all_authorization_stores (priv);
}

static void
polkit_backend_local_authority_finalize (PolkitBackendLocalAuthorityPrivate *priv)
{
  purge_all_authorization_stores (priv);

  g_strfreev (priv->authorization_store_paths);
}

static void
polkit_backend_local_authority_set_auth_store_paths (PolkitBackendLocalAuthorityPrivate *priv, const char *paths)
{
  g_strfreev (priv->authorization_store_paths);
  priv->authorization_store_paths = g_strsplit (paths, ";", 0);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
update_ret_from_authorization_store (PolkitBackendLocalAuthorityPrivate *priv,
				     PolkitImplicitAuthorization *ret,
				     PolkitIdentity *identity,
				     gboolean subject_is_local,
				     gboolean subject_is_active,
				     const gchar *action_id,
				     PolkitDetails *details)
{
  GList *l;

  for (l = priv->authorization_stores; l != NULL; l = l->next)
    {
      PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (l->data);
      PolkitImplicitAuthorization ret_any;
      PolkitImplicitAuthorization ret_inactive;
      PolkitImplicitAuthorization ret_active;

      if (polkit_backend_local_authorization_store_lookup (store, identity,
							   action_id, details,
							   &ret_any,
							   &ret_inactive,
							   &ret_active))
	{
	  PolkitImplicitAuthorization relevant_ret;

	  if (subject_is_local && subject_is_active)
	    relevant_ret = ret_active;
	  else if (subject_is_local)
	    relevant_ret = ret_inactive;
	  else
	    relevant_ret = ret_any;
	  if (relevant_ret != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
	    *ret = relevant_ret;
	}
    }
}

static PolkitImplicitAuthorization
polkit_backend_local_authority_check_authorization_sync (PolkitBackendLocalAuthorityPrivate *priv,
                                                         PolkitIdentity                    *user_for_subject,
                                                         gboolean                           subject_is_local,
                                                         gboolean                           subject_is_active,
                                                         const gchar                       *action_id,
                                                         PolkitDetails                     *details)
{
  PolkitImplicitAuthorization ret;
  GList *groups;
  GList *ll;

  ret = POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN;

#if 0
  g_debug ("local: checking `%s' for subject `%s' (user `%s')",
           action_id,
           polkit_subject_to_string (subject),
           polkit_identity_to_string (user_for_subject));
#endif

  /* First check for default entries */
  update_ret_from_authorization_store (priv, &ret, NULL,
				       subject_is_local, subject_is_active,
				       action_id, details);

  /* Then lookup for all groups the user belong to */
  groups = get_groups_for_user (user_for_subject);
  for (ll = groups; ll != NULL; ll = ll->next)
    {
      PolkitIdentity *group = POLKIT_IDENTITY (ll->data);

      update_ret_from_authorization_store (priv, &ret, group,
					   subject_is_local, subject_is_active,
					   action_id, details);
    }
  g_list_foreach (groups, (GFunc) g_object_unref, NULL);
  g_list_free (groups);

  /* Then do it for the user */
  update_ret_from_authorization_store (priv, &ret, user_for_subject,
				       subject_is_local, subject_is_active,
				       action_id, details);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static GList *
get_groups_for_user (PolkitIdentity *user)
{
  uid_t uid;
  struct passwd *passwd;
  GList *result;
  gid_t groups[512];
  int num_groups = 512;
  int n;

  result = NULL;

  /* TODO: it would be, uhm, good to cache this information */

  uid = polkit_unix_user_get_uid (POLKIT_UNIX_USER (user));
  passwd = getpwuid (uid);
  if (passwd == NULL)
    {
      g_warning ("No user with uid %d", uid);
      goto out;
    }

  /* TODO: should resize etc etc etc */

  if (getgrouplist (passwd->pw_name,
                    passwd->pw_gid,
                    groups,
                    &num_groups) < 0)
    {
      g_warning ("Error looking up groups for uid %d: %s", uid, g_strerror (errno));
      goto out;
    }

  for (n = 0; n < num_groups; n++)
    result = g_list_prepend (result, polkit_unix_group_new (groups[n]));

 out:

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
parse_boolean (const char *arg, GError **error)
{
  if (strcmp (arg, "true") == 0)
    return TRUE;
  if (strcmp (arg, "false") == 0)
    return FALSE;
  g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
	       _("Invalid boolean value"));
  return FALSE;
}

static gchar *auth_paths; /* = NULL; */

/* Use G_OPTION_ARG_FILENAME for all strings to avoid the conversion to
   UTF-8. */
static const GOptionEntry opt_entries[] =
  {
    { "paths", 'p', 0, G_OPTION_ARG_FILENAME, &auth_paths,
      N_("Use authorization 'top' directories in ;-separated PATH"), N_("PATH"),
    },
    { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
  };

int
main (int argc, char *argv[])
{
  GError *error;
  GOptionContext *opt_context;
  PolkitBackendLocalAuthorityPrivate priv;
  PolkitIdentity *user_for_subject = NULL;
  gboolean subject_is_local, subject_is_active;
  PolkitDetails *details;
  PolkitImplicitAuthorization result;

  g_type_init ();

  opt_context = g_option_context_new ("USER LOCAL? ACTIVE? ACTION");
  g_option_context_set_summary (opt_context,
				N_("Interprets pklocalauthority(8) "
				   "authorization files."));
  g_option_context_add_main_entries (opt_context, opt_entries, PACKAGE_NAME);
  error = NULL;
  if (!g_option_context_parse (opt_context, &argc, &argv, &error))
    {
      fprintf (stderr, _("%s: %s\n"
			 "Run `%s --help' for more information.\n"),
	       g_get_prgname (), error->message, g_get_prgname ());
      g_error_free (error);
      g_option_context_free (opt_context);
      goto error;
    }
  g_option_context_free (opt_context);
  if (argc != 5)
    {
      fprintf (stderr, _("%s: unexpected number of arguments\n"
			 "Run `%s --help' for more information.\n"),
	       g_get_prgname (), g_get_prgname ());
      goto error;
    }

  if (auth_paths == NULL)
    auth_paths = g_strdup (PACKAGE_LOCALSTATE_DIR "/lib/polkit-1/localauthority;"
			   PACKAGE_SYSCONF_DIR "/polkit-1/localauthority");
  g_debug ("Using authorization directory paths `%s'", auth_paths);

  memset (&priv, 0, sizeof (priv));
  polkit_backend_local_authority_init (&priv);
  /* "Local Authorization Store Paths",
     "Semi-colon separated list of Authorization Store 'top' directories." */
  polkit_backend_local_authority_set_auth_store_paths (&priv, auth_paths);
  polkit_backend_local_authority_constructed (&priv);

  user_for_subject = polkit_unix_user_new_for_name(argv[1], &error);
  if (user_for_subject == NULL)
    {
      fprintf (stderr, _("%s: Invalid user `%s': %s\n"), g_get_prgname(),
	       argv[1], error->message);
      g_error_free (error);
      goto error_priv;
    }
  subject_is_local = parse_boolean (argv[2], &error);
  if (error != NULL)
    {
      fprintf (stderr, _("%s: Invalid boolean `%s': %s\n"), g_get_prgname(),
	       argv[2], error->message);
      g_error_free (error);
      goto error_priv;
    }
  subject_is_active = parse_boolean(argv[3], &error);
  if (error != NULL)
    {
      fprintf (stderr, _("%s: Invalid boolean `%s': %s\n"), g_get_prgname(),
	       argv[3], error->message);
      g_error_free (error);
      goto error_priv;
    }

  /* polkitlocalauthority used to be able to change details, but that is no
     longer supported in the JS authority, and was not apparently used
     anyway.  Just submit a dummy object. */
  details = polkit_details_new ();
  result = polkit_backend_local_authority_check_authorization_sync
    (&priv, user_for_subject, subject_is_local, subject_is_active, argv[4],
     details);
  g_object_unref (details);

  g_object_unref (user_for_subject);
  polkit_backend_local_authority_finalize (&priv);

  if (result != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
    printf ("%s\n", polkit_implicit_authorization_to_string (result));

  return 0;

 error_priv:
  g_object_unref (user_for_subject);
  polkit_backend_local_authority_finalize (&priv);
 error:
  g_free (auth_paths);
  return EXIT_FAILURE;
}
