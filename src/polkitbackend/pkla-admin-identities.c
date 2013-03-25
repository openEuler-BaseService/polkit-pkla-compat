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

/* FIXME: drop the defines and limit to standard APIs? */
#define _POLKIT_COMPILATION
#define _POLKIT_BACKEND_COMPILATION
#include <polkit/polkit.h>
#include "polkitbackendconfigsource.h"
#include "polkitbackendlocalauthority.h"

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

static GList *get_users_in_group (PolkitIdentity              *group,
                                  gboolean                     include_root);

static GList *get_users_in_net_group (PolkitIdentity          *group,
                                      gboolean                 include_root);

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  gchar *config_path;
  PolkitBackendConfigSource *config_source;
} PolkitBackendLocalAuthorityPrivate;

/* ---------------------------------------------------------------------------------------------------- */

enum
{
  PROP_0,

  // Path overrides used for unit testing
  PROP_CONFIG_PATH,
};

/* ---------------------------------------------------------------------------------------------------- */

static GList *polkit_backend_local_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *authority,
                                                                        PolkitSubject                     *caller,
                                                                        PolkitSubject                     *subject,
                                                                        PolkitIdentity                    *user_for_subject,
									gboolean                           subject_is_local,
									gboolean                           subject_is_active,
                                                                        const gchar                       *action_id,
                                                                        PolkitDetails                     *details);

G_DEFINE_TYPE (PolkitBackendLocalAuthority,
	       polkit_backend_local_authority,
	       POLKIT_BACKEND_TYPE_INTERACTIVE_AUTHORITY);

#define POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_BACKEND_TYPE_LOCAL_AUTHORITY, PolkitBackendLocalAuthorityPrivate))

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_init (PolkitBackendLocalAuthority *authority)
{
  PolkitBackendLocalAuthorityPrivate *priv;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

  priv->config_path = NULL;
}

static void
polkit_backend_local_authority_constructed (GObject *object)
{
  PolkitBackendLocalAuthority *authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  GFile *config_directory;

  authority = POLKIT_BACKEND_LOCAL_AUTHORITY (object);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

  g_debug ("Using config directory `%s'", priv->config_path);
  config_directory = g_file_new_for_path (priv->config_path);
  priv->config_source = polkit_backend_config_source_new (config_directory);
  g_object_unref (config_directory);

  G_OBJECT_CLASS (polkit_backend_local_authority_parent_class)->constructed (object);
}

static void
polkit_backend_local_authority_finalize (GObject *object)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (object);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  if (priv->config_source != NULL)
    g_object_unref (priv->config_source);

  g_free (priv->config_path);

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
      case PROP_CONFIG_PATH:
        g_free (priv->config_path);
        priv->config_path = g_value_dup_string (value);
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
  interactive_authority_class->get_admin_identities     = polkit_backend_local_authority_get_admin_auth_identities;

  pspec = g_param_spec_string ("config-path",
                               "Local Authority Configuration Path",
                               "Path to directory of LocalAuthority config files.",
                               PACKAGE_SYSCONF_DIR "/polkit-1/localauthority.conf.d",
                               G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE);
  g_object_class_install_property (gobject_class, PROP_CONFIG_PATH, pspec);

  g_type_class_add_private (klass, sizeof (PolkitBackendLocalAuthorityPrivate));
}

static GList *
polkit_backend_local_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *authority,
                                                          PolkitSubject                     *caller,
                                                          PolkitSubject                     *subject,
                                                          PolkitIdentity                    *user_for_subject,
							  gboolean                           subject_is_local,
							  gboolean                           subject_is_active,
                                                          const gchar                       *action_id,
                                                          PolkitDetails                     *details)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  GList *ret;
  guint n;
  gchar **admin_identities;
  GError *error;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  ret = NULL;

  error = NULL;
  admin_identities = polkit_backend_config_source_get_string_list (priv->config_source,
                                                                   "Configuration",
                                                                   "AdminIdentities",
                                                                   &error);
  if (admin_identities == NULL)
    {
      g_warning ("Error getting admin_identities configuration item: %s", error->message);
      g_error_free (error);
      goto out;
    }

  for (n = 0; admin_identities[n] != NULL; n++)
    {
      PolkitIdentity *identity;

      error = NULL;
      identity = polkit_identity_from_string (admin_identities[n], &error);
      if (identity == NULL)
        {
          g_warning ("Error parsing identity %s: %s", admin_identities[n], error->message);
          g_error_free (error);
          continue;
        }

      if (POLKIT_IS_UNIX_USER (identity))
        {
          ret = g_list_append (ret, identity);
        }
      else if (POLKIT_IS_UNIX_GROUP (identity))
        {
          ret = g_list_concat (ret, get_users_in_group (identity, FALSE));
        }
      else if (POLKIT_IS_UNIX_NETGROUP (identity))
        {
          ret =  g_list_concat (ret, get_users_in_net_group (identity, FALSE));
        }
      else
        {
          g_warning ("Unsupported identity %s", admin_identities[n]);
        }
    }

  g_strfreev (admin_identities);

 out:

  /* default to uid 0 if no admin identities has been found */
  if (ret == NULL)
    ret = g_list_prepend (ret, polkit_unix_user_new (0));

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static GList *
get_users_in_group (PolkitIdentity                    *group,
                    gboolean                           include_root)
{
  gid_t gid;
  struct group *grp;
  GList *ret;
  guint n;

  ret = NULL;

  gid = polkit_unix_group_get_gid (POLKIT_UNIX_GROUP (group));
  grp = getgrgid (gid);
  if (grp == NULL)
    {
      g_warning ("Error looking up group with gid %d: %s", gid, g_strerror (errno));
      goto out;
    }

  for (n = 0; grp->gr_mem != NULL && grp->gr_mem[n] != NULL; n++)
    {
      PolkitIdentity *user;
      GError *error;

      if (!include_root && g_strcmp0 (grp->gr_mem[n], "root") == 0)
        continue;

      error = NULL;
      user = polkit_unix_user_new_for_name (grp->gr_mem[n], &error);
      if (user == NULL)
        {
          g_warning ("Unknown username '%s' in group: %s", grp->gr_mem[n], error->message);
          g_error_free (error);
        }
      else
        {
          ret = g_list_prepend (ret, user);
        }
    }

  ret = g_list_reverse (ret);

 out:
  return ret;
}

static GList *
get_users_in_net_group (PolkitIdentity                    *group,
                        gboolean                           include_root)
{
  const gchar *name;
  GList *ret;

  ret = NULL;
  name = polkit_unix_netgroup_get_name (POLKIT_UNIX_NETGROUP (group));

  if (setnetgrent (name) == 0)
    {
      g_warning ("Error looking up net group with name %s: %s", name, g_strerror (errno));
      goto out;
    }

  for (;;)
    {
      char *hostname, *username, *domainname;
      PolkitIdentity *user;
      GError *error = NULL;

      if (getnetgrent (&hostname, &username, &domainname) == 0)
        break;

      /* Skip NULL entries since we never want to make everyone an admin
       * Skip "-" entries which mean "no match ever" in netgroup land */
      if (username == NULL || g_strcmp0 (username, "-") == 0)
        continue;

      /* TODO: Should we match on hostname? Maybe only allow "-" as a hostname
       * for safety. */

      user = polkit_unix_user_new_for_name (username, &error);
      if (user == NULL)
        {
          g_warning ("Unknown username '%s' in unix-netgroup: %s", username, error->message);
          g_error_free (error);
        }
      else
        {
          ret = g_list_prepend (ret, user);
        }
    }

  ret = g_list_reverse (ret);

 out:
  endnetgrent ();
  return ret;
}


int
main (void)
{
  return 0;
}
