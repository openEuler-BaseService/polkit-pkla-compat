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
#include <string.h>
#include <glib/gstdio.h>
#include <locale.h>
#include <glib/gi18n-lib.h>

/* FIXME: build this properly stand-alone */
#define _POLKIT_COMPILATION
#define _POLKIT_BACKEND_COMPILATION
#include <polkit/polkit.h>
#include "polkitbackendlocalauthority.h"
#include "polkitbackendlocalauthorizationstore.h"

#include <polkit/polkitprivate.h>

/**
 * SECTION:polkitbackendlocalauthority
 * @title: PolkitBackendLocalAuthority
 * @short_description: Local Authority
 * @stability: Unstable
 *
 * An implementation of #PolkitBackendAuthority that stores
 * authorizations on the local file system, supports interaction with
 * authentication agents (virtue of being based on
 * #PolkitBackendInteractiveAuthority).
 */

/* ---------------------------------------------------------------------------------------------------- */

static GList *get_groups_for_user (PolkitIdentity              *user);

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  gchar **authorization_store_paths;
  GList *authorization_stores;
  GList *authorization_store_monitors;

} PolkitBackendLocalAuthorityPrivate;

/* ---------------------------------------------------------------------------------------------------- */

enum
{
  PROP_0,

  // Path overrides used for unit testing
  PROP_AUTH_STORE_PATHS,
};

/* ---------------------------------------------------------------------------------------------------- */

static PolkitImplicitAuthorization polkit_backend_local_authority_check_authorization_sync (
                                                          PolkitBackendInteractiveAuthority *authority,
                                                          PolkitSubject                     *caller,
                                                          PolkitSubject                     *subject,
                                                          PolkitIdentity                    *user_for_subject,
                                                          gboolean                           subject_is_local,
                                                          gboolean                           subject_is_active,
                                                          const gchar                       *action_id,
                                                          PolkitDetails                     *details,
                                                          PolkitImplicitAuthorization        implicit);

G_DEFINE_TYPE (PolkitBackendLocalAuthority,
	       polkit_backend_local_authority,
	       POLKIT_BACKEND_TYPE_INTERACTIVE_AUTHORITY);

#define POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_BACKEND_TYPE_LOCAL_AUTHORITY, PolkitBackendLocalAuthorityPrivate))

/* ---------------------------------------------------------------------------------------------------- */

static void
on_store_changed (PolkitBackendLocalAuthorizationStore *store,
                  gpointer                              user_data)
{
  PolkitBackendLocalAuthority *authority = POLKIT_BACKEND_LOCAL_AUTHORITY (user_data);

  g_signal_emit_by_name (authority, "changed");
}

/* ---------------------------------------------------------------------------------------------------- */

static void
purge_all_authorization_stores (PolkitBackendLocalAuthority *authority)
{
  PolkitBackendLocalAuthorityPrivate *priv;
  GList *l;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

  for (l = priv->authorization_stores; l != NULL; l = l->next)
    {
      PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (l->data);
      g_signal_handlers_disconnect_by_func (store,
                                            G_CALLBACK (on_store_changed),
                                            authority);
      g_object_unref (store);
    }
  g_list_free (priv->authorization_stores);
  priv->authorization_stores = NULL;

  g_debug ("Purged all local authorization stores");
}

/* ---------------------------------------------------------------------------------------------------- */

static void
add_one_authorization_store (PolkitBackendLocalAuthority *authority,
                             GFile                       *directory)
{
  PolkitBackendLocalAuthorizationStore *store;
  PolkitBackendLocalAuthorityPrivate *priv;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

  store = polkit_backend_local_authorization_store_new (directory, ".pkla");
  priv->authorization_stores = g_list_append (priv->authorization_stores, store);

  g_signal_connect (store,
                    "changed",
                    G_CALLBACK (on_store_changed),
                    authority);
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
add_all_authorization_stores (PolkitBackendLocalAuthority *authority)
{
  PolkitBackendLocalAuthorityPrivate *priv;
  guint n;
  GList *directories;
  GList *l;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);
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

      add_one_authorization_store (authority, directory);
    }

  g_list_foreach (directories, (GFunc) g_object_unref, NULL);
  g_list_free (directories);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
on_toplevel_authority_store_monitor_changed (GFileMonitor     *monitor,
                                             GFile            *file,
                                             GFile            *other_file,
                                             GFileMonitorEvent event_type,
                                             gpointer          user_data)
{
  PolkitBackendLocalAuthority *authority = POLKIT_BACKEND_LOCAL_AUTHORITY (user_data);

  purge_all_authorization_stores (authority);
  add_all_authorization_stores (authority);
}

static void
polkit_backend_local_authority_init (PolkitBackendLocalAuthority *authority)
{
  PolkitBackendLocalAuthorityPrivate *priv;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

  priv->authorization_store_paths = NULL;
}

static void
polkit_backend_local_authority_constructed (GObject *object)
{
  PolkitBackendLocalAuthority *authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  guint n;

  authority = POLKIT_BACKEND_LOCAL_AUTHORITY (object);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

  add_all_authorization_stores (authority);

  /* Monitor the toplevels */
  priv->authorization_store_monitors = NULL;
  for (n = 0; priv->authorization_store_paths && priv->authorization_store_paths[n]; n++)
    {
      const gchar *toplevel_path;
      GFile *toplevel_directory;
      GFileMonitor *monitor;
      GError *error;

      toplevel_path = priv->authorization_store_paths[n];
      toplevel_directory = g_file_new_for_path (toplevel_path);

      error = NULL;
      monitor = g_file_monitor_directory (toplevel_directory,
                                          G_FILE_MONITOR_NONE,
                                          NULL,
                                          &error);
      if (monitor == NULL)
        {
          g_warning ("Error creating file monitor for %s: %s", toplevel_path, error->message);
          g_error_free (error);
          g_object_unref (toplevel_directory);
          continue;
        }

      g_debug ("Monitoring `%s' for changes", toplevel_path);

      g_signal_connect (monitor,
                        "changed",
                        G_CALLBACK (on_toplevel_authority_store_monitor_changed),
                        authority);

      priv->authorization_store_monitors = g_list_append (priv->authorization_store_monitors, monitor);

      g_object_unref (toplevel_directory);
    }

  G_OBJECT_CLASS (polkit_backend_local_authority_parent_class)->constructed (object);
}

static void
polkit_backend_local_authority_finalize (GObject *object)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (object);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  purge_all_authorization_stores (local_authority);

  g_list_free_full (priv->authorization_store_monitors, g_object_unref);

  g_strfreev (priv->authorization_store_paths);

  G_OBJECT_CLASS (polkit_backend_local_authority_parent_class)->finalize (object);
}

static const gchar *
polkit_backend_local_authority_get_name (PolkitBackendAuthority *authority)
{
  return "local";
}

static const gchar *
polkit_backend_local_authority_get_version (PolkitBackendAuthority *authority)
{
  return PACKAGE_VERSION;
}

static PolkitAuthorityFeatures
polkit_backend_local_authority_get_features (PolkitBackendAuthority *authority)
{
  return POLKIT_AUTHORITY_FEATURES_TEMPORARY_AUTHORIZATION;
}

static void
polkit_backend_local_authority_set_property (GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (object);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  switch (property_id)
    {
      case PROP_AUTH_STORE_PATHS:
        g_strfreev (priv->authorization_store_paths);
        priv->authorization_store_paths = g_strsplit (g_value_get_string (value), ";", 0);
        break;
      default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
polkit_backend_local_authority_class_init (PolkitBackendLocalAuthorityClass *klass)
{
  GObjectClass *gobject_class;
  PolkitBackendAuthorityClass *authority_class;
  PolkitBackendInteractiveAuthorityClass *interactive_authority_class;
  GParamSpec *pspec;

  gobject_class = G_OBJECT_CLASS (klass);
  authority_class = POLKIT_BACKEND_AUTHORITY_CLASS (klass);
  interactive_authority_class = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_CLASS (klass);

  gobject_class->set_property                           = polkit_backend_local_authority_set_property;
  gobject_class->finalize                               = polkit_backend_local_authority_finalize;
  gobject_class->constructed                            = polkit_backend_local_authority_constructed;
  authority_class->get_name                             = polkit_backend_local_authority_get_name;
  authority_class->get_version                          = polkit_backend_local_authority_get_version;
  authority_class->get_features                         = polkit_backend_local_authority_get_features;
  interactive_authority_class->check_authorization_sync = polkit_backend_local_authority_check_authorization_sync;

  pspec = g_param_spec_string ("auth-store-paths",
                               "Local Authorization Store Paths",
                               "Semi-colon separated list of Authorization Store 'top' directories.",
                               PACKAGE_LOCALSTATE_DIR "/lib/polkit-1/localauthority;"
                               PACKAGE_SYSCONF_DIR "/polkit-1/localauthority",
                               G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE);
  g_object_class_install_property (gobject_class, PROP_AUTH_STORE_PATHS, pspec);

  g_type_class_add_private (klass, sizeof (PolkitBackendLocalAuthorityPrivate));
}

/* ---------------------------------------------------------------------------------------------------- */

static PolkitImplicitAuthorization
polkit_backend_local_authority_check_authorization_sync (PolkitBackendInteractiveAuthority *authority,
                                                         PolkitSubject                     *caller,
                                                         PolkitSubject                     *subject,
                                                         PolkitIdentity                    *user_for_subject,
                                                         gboolean                           subject_is_local,
                                                         gboolean                           subject_is_active,
                                                         const gchar                       *action_id,
                                                         PolkitDetails                     *details,
                                                         PolkitImplicitAuthorization        implicit)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  PolkitImplicitAuthorization ret;
  PolkitImplicitAuthorization ret_any;
  PolkitImplicitAuthorization ret_inactive;
  PolkitImplicitAuthorization ret_active;
  GList *groups;
  GList *l, *ll;

  ret = implicit;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

#if 0
  g_debug ("local: checking `%s' for subject `%s' (user `%s')",
           action_id,
           polkit_subject_to_string (subject),
           polkit_identity_to_string (user_for_subject));
#endif

  /* First lookup for all groups the user belong to */
  groups = get_groups_for_user (user_for_subject);
  for (ll = groups; ll != NULL; ll = ll->next)
    {
      PolkitIdentity *group = POLKIT_IDENTITY (ll->data);

      for (l = priv->authorization_stores; l != NULL; l = l->next)
        {
          PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (l->data);

          if (polkit_backend_local_authorization_store_lookup (store,
                                                               group,
                                                               action_id,
                                                               details,
                                                               &ret_any,
                                                               &ret_inactive,
                                                               &ret_active))
            {
              if (subject_is_local && subject_is_active)
                {
                  if (ret_active != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                    ret = ret_active;
                }
              else if (subject_is_local)
                {
                  if (ret_inactive != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                    ret = ret_inactive;
                }
              else
                {
                  if (ret_any != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                    ret = ret_any;
                }
            }
        }
    }
  g_list_foreach (groups, (GFunc) g_object_unref, NULL);
  g_list_free (groups);

  /* Then do it for the user */
  for (l = priv->authorization_stores; l != NULL; l = l->next)
    {
      PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (l->data);

      if (polkit_backend_local_authorization_store_lookup (store,
                                                           user_for_subject,
                                                           action_id,
                                                           details,
                                                           &ret_any,
                                                           &ret_inactive,
                                                           &ret_active))
        {
          if (subject_is_local && subject_is_active)
            {
              if (ret_active != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                ret = ret_active;
            }
          else if (subject_is_local)
            {
              if (ret_inactive != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                ret = ret_inactive;
            }
          else
            {
              if (ret_any != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                ret = ret_any;
            }
        }
    }

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

int
main (void)
{
  return 0;
}
