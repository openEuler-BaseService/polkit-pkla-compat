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
#include <stdlib.h>
#include <string.h>
#include <glib/gstdio.h>
#include <locale.h>
#include <glib/gi18n.h>
#include <polkit/polkit.h>

#include "polkitbackendconfigsource.h"

static GList *
polkit_backend_local_authority_get_admin_auth_identities (PolkitBackendConfigSource *config_source)
{
  GList *ret;
  guint n;
  gchar **admin_identities;
  GError *error;

  ret = NULL;

  error = NULL;
  admin_identities = polkit_backend_config_source_get_string_list (config_source,
                                                                   "Configuration",
                                                                   "AdminIdentities",
                                                                   &error);
  if (admin_identities == NULL)
    {
      if (g_error_matches (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND))
	/* Can happen if the configuration is in a JavaScript .rule */
	g_debug ("Error getting admin_identities configuration item: %s",
		 error->message);
      else
	g_warning ("Error getting admin_identities configuration item: %s",
		   error->message);
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

      ret = g_list_append (ret, identity);
    }

  g_strfreev (admin_identities);

 out:

  return ret;
}

static gchar *config_path; /* = NULL; */

/* Use G_OPTION_ARG_FILENAME for all strings to avoid the conversion to
   UTF-8. */
static const GOptionEntry opt_entries[] =
  {
    { "config-path", 'c', 0, G_OPTION_ARG_FILENAME, &config_path,
      N_("Use configuration files in DIR"), N_("DIR"),
    },
    { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
  };

int
main (int argc, char *argv[])
{
  GError *error;
  GOptionContext *opt_context;
  GFile *config_directory;
  PolkitBackendConfigSource *config_source;
  GList *identities, *l;

  g_type_init ();

  opt_context = g_option_context_new ("");
  g_option_context_set_summary (opt_context,
				N_("Interprets pklocalauthority(8) "
				   "configuration files."));
  g_option_context_add_main_entries (opt_context, opt_entries, PACKAGE_NAME);
  error = NULL;
  if (!g_option_context_parse (opt_context, &argc, &argv, &error))
    {
      fprintf (stderr, _("%s: %s\n"
			 "Run `%s --help' for more information.\n"),
	       g_get_prgname (), error->message, g_get_prgname ());
      g_error_free (error);
      g_option_context_free (opt_context);
      return EXIT_FAILURE;
    }
  g_option_context_free (opt_context);
  if (argc != 1)
    {
      fprintf (stderr, _("%s: unexpected argument\n"
			 "Run `%s --help' for more information.\n"),
	       g_get_prgname (), g_get_prgname ());
      return EXIT_FAILURE;
    }

  if (config_path == NULL)
    config_path = g_strdup (PACKAGE_SYSCONF_DIR
			    "/polkit-1/localauthority.conf.d");
  g_debug ("Using config directory `%s'", config_path);
  config_directory = g_file_new_for_path (config_path);
  g_free (config_path);

  config_source = polkit_backend_config_source_new (config_directory);
  g_object_unref (config_directory);

  identities = polkit_backend_local_authority_get_admin_auth_identities (config_source);
  for (l = identities; l != NULL; l = l->next)
    {
      PolkitIdentity *identity;
      gchar *s;

      identity = POLKIT_IDENTITY (l->data);
      s = polkit_identity_to_string (identity);
      printf ("%s\n", s);
      g_free (s);
    }
  g_list_foreach (identities, (GFunc) g_object_unref, NULL);
  g_list_free (identities);

  g_object_unref (config_source);

  return 0;
}
