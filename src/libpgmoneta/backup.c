/*
 * Copyright (C) 2025 The pgmoneta community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* pgmoneta */
#include <pgmoneta.h>
#include <aes.h>
#include <art.h>
#include <backup.h>
#include <compression.h>
#include <info.h>
#include <logging.h>
#include <management.h>
#include <network.h>
#include <security.h>
#include <utils.h>
#include <workflow.h>

#define NAME "backup"

void
pgmoneta_backup(int client_fd, int server, uint8_t compression, uint8_t encryption, struct json* payload)
{
   bool active = false;
   char date_str[128];
   char* date = NULL;
   char* elapsed = NULL;
   char* incremental = NULL;
   char* incremental_base = NULL;
   struct tm* time_info;
   struct timespec start_t;
   struct timespec end_t;
   time_t curr_t;
   double total_seconds;
   char* en = NULL;
   int ec = -1;
   int backup_index = -1;
   char* server_backup = NULL;
   char* root = NULL;
   char* d = NULL;
   char* backup_dir = NULL;
   unsigned long size;
   bool backup_incremental = false;
   int number_of_backups = 0;
   struct backup** backups = NULL;
   struct workflow* workflow = NULL;
   struct art* nodes = NULL;
   struct backup* backup = NULL;
   struct backup* child = NULL;
   struct json* req = NULL;
   struct json* response = NULL;
   struct main_configuration* config;
   struct backup* temp_backup = NULL;

   pgmoneta_start_logging();

   config = (struct main_configuration*)shmem;

   if (!config->common.servers[server].valid)
   {
      ec = MANAGEMENT_ERROR_BACKUP_INVALID;
      pgmoneta_log_error("Backup: Server %s is not in a valid configuration", config->common.servers[server].name);
      goto error;
   }

   if (!config->common.servers[server].wal_streaming)
   {
      ec = MANAGEMENT_ERROR_BACKUP_WAL;
      pgmoneta_log_error("Backup: Server %s is not WAL streaming", config->common.servers[server].name);
      goto error;
   }

   if (!atomic_compare_exchange_strong(&config->common.servers[server].repository, &active, true))
   {
      ec = MANAGEMENT_ERROR_BACKUP_ACTIVE;
      pgmoneta_log_info("Backup: Server %s is active", config->common.servers[server].name);
      goto error;
   }

   config->common.servers[server].active_backup = true;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &start_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &start_t);
#endif

   curr_t = time(NULL);
   memset(&date_str[0], 0, sizeof(date_str));
   time_info = localtime(&curr_t);
   req = (struct json*)pgmoneta_json_get(payload, MANAGEMENT_CATEGORY_REQUEST);
   incremental = (char*)pgmoneta_json_get(req, MANAGEMENT_ARGUMENT_BACKUP);

   strftime(&date_str[0], sizeof(date_str), "%Y%m%d%H%M%S", time_info);

   date = pgmoneta_append(date, &date_str[0]);

   server_backup = pgmoneta_get_server_backup(server);
   root = pgmoneta_get_server_backup_identifier(server, date);

   if (pgmoneta_art_create(&nodes))
   {
      goto error;
   }

   if (pgmoneta_art_insert(nodes, USER_SERVER, (uintptr_t)config->common.servers[server].name, ValueString))
   {
      goto error;
   }

   if (pgmoneta_art_insert(nodes, NODE_SERVER_ID, (uintptr_t)server, ValueInt32))
   {
      goto error;
   }

   if (pgmoneta_art_insert(nodes, USER_IDENTIFIER, (uintptr_t)date, ValueString))
   {
      goto error;
   }

   if (pgmoneta_art_insert(nodes, NODE_LABEL, (uintptr_t)date, ValueString))
   {
      goto error;
   }

   if (incremental != NULL)
   {
      backup_incremental = false;
      if (config->common.servers[server].version < 17)
      {
         pgmoneta_log_error("Incremental backup not supported for server %s at version %d",
                            config->common.servers[server].name, config->common.servers[server].version);
         goto error;
      }
      else
      {
         backup_incremental = true;
      }
   }

   if (backup_incremental)
   {
      if (pgmoneta_load_infos(server_backup, &number_of_backups, &backups))
      {
         ec = MANAGEMENT_ERROR_BACKUP_NOBACKUPS;
         goto error;
      }

      if (number_of_backups == 0)
      {
         ec = MANAGEMENT_ERROR_BACKUP_NOBACKUPS;
         goto error;
      }

      if (!strcmp(incremental, "oldest"))
      {
         backup_index = 0;
      }
      else if (!strcmp(incremental, "latest") || !strcmp(incremental, "newest"))
      {
         backup_index = number_of_backups - 1;
      }
      else
      {
         for (int i = 0; backup_index == -1 && i < number_of_backups; i++)
         {
            if (!strcmp(backups[i]->label, incremental))
            {
               backup_index = i;
            }
         }
      }

      if (backup_index == -1)
      {
         ec = MANAGEMENT_ERROR_BACKUP_NOBACKUPS;
         pgmoneta_log_error("Backup: No incremental identifier for %s/%s", config->common.servers[server].name, incremental);
         goto error;
      }

      if (pgmoneta_get_backup_child(server, backups[backup_index], &child))
      {
         ec = MANAGEMENT_ERROR_BACKUP_NOCHILD;
         pgmoneta_log_error("Backup: Unable to scan for children for %s/%s", config->common.servers[server].name, incremental);
         goto error;
      }

      if (child != NULL)
      {
         ec = MANAGEMENT_ERROR_BACKUP_ALREADYCHILD;
         pgmoneta_log_error("Backup: Already an incremental backup for %s/%s", config->common.servers[server].name, incremental);
         goto error;
      }

      incremental_base = pgmoneta_get_server_backup_identifier(server, backups[backup_index]->label);

      pgmoneta_art_insert(nodes, NODE_INCREMENTAL_BASE, (uintptr_t) incremental_base, ValueString);
      pgmoneta_art_insert(nodes, NODE_INCREMENTAL_LABEL, (uintptr_t)backups[backup_index]->label, ValueString);

      workflow = pgmoneta_workflow_create(WORKFLOW_TYPE_INCREMENTAL_BACKUP, NULL);
   }
   else
   {
      workflow = pgmoneta_workflow_create(WORKFLOW_TYPE_BACKUP, NULL);
   }

   pgmoneta_mkdir(root);

   if (pgmoneta_workflow_execute(workflow, nodes, &en, &ec))
   {
      goto error;
   }

   backup_dir = pgmoneta_get_server_backup_identifier(server, date);
   backup_dir = pgmoneta_append(backup_dir, "/data");
   size = pgmoneta_directory_size(backup_dir);

   if (pgmoneta_load_info(server_backup, date, &temp_backup))
   {
      ec = MANAGEMENT_ERROR_BACKUP_ERROR;
      goto error;
   }
   temp_backup->backup_size = size;
   if (pgmoneta_save_info(server_backup, temp_backup))
   {
      ec = MANAGEMENT_ERROR_BACKUP_ERROR;
      goto error;
   }
   free(temp_backup);
   temp_backup = NULL;
   if (pgmoneta_management_create_response(payload, server, &response))
   {
      ec = MANAGEMENT_ERROR_ALLOCATION;
      goto error;
   }

   if (pgmoneta_load_info(server_backup, date, &backup))
   {
      ec = MANAGEMENT_ERROR_BACKUP_ERROR;
      goto error;
   }

   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_SERVER, (uintptr_t)config->common.servers[server].name, ValueString);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_BACKUP, (uintptr_t)date, ValueString);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_BACKUP_SIZE, (uintptr_t)backup->backup_size, ValueUInt64);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_RESTORE_SIZE, (uintptr_t)backup->restore_size, ValueUInt64);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_BIGGEST_FILE_SIZE, (uintptr_t)backup->biggest_file_size, ValueUInt64);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_COMPRESSION, (uintptr_t)backup->compression, ValueInt32);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_ENCRYPTION, (uintptr_t)backup->encryption, ValueInt32);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_VALID, (uintptr_t)backup->valid, ValueInt8);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_INCREMENTAL, (uintptr_t)backup->type, ValueBool);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_INCREMENTAL_PARENT, (uintptr_t)backup->parent_label, ValueString);

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &end_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &end_t);
#endif

   elapsed = pgmoneta_get_timestamp_string(start_t, end_t, &total_seconds);

   if (pgmoneta_load_info(server_backup, date, &temp_backup))
   {
      ec = MANAGEMENT_ERROR_BACKUP_ERROR;
      goto error;
   }
   temp_backup->total_elapsed_time = total_seconds;
   if (pgmoneta_save_info(server_backup, temp_backup))
   {
      ec = MANAGEMENT_ERROR_BACKUP_ERROR;
      goto error;
   }

   if (pgmoneta_management_response_ok(NULL, client_fd, start_t, end_t, compression, encryption, payload))
   {
      ec = MANAGEMENT_ERROR_BACKUP_NETWORK;
      pgmoneta_log_error("Backup: Error sending response for %s", config->common.servers[server].name);
      goto error;
   }

   pgmoneta_log_info("Backup: %s/%s (Elapsed: %s)", config->common.servers[server].name, date, elapsed);

   config->common.servers[server].active_backup = false;
   atomic_store(&config->common.servers[server].repository, false);

   pgmoneta_json_destroy(payload);

   pgmoneta_workflow_destroy(workflow);

   pgmoneta_art_destroy(nodes);

   free(date);
   for (int i = 0; i < number_of_backups; i++)
   {
      free(backups[i]);
   }
   free(temp_backup);
   free(backups);
   free(backup);
   free(child);
   free(backup_dir);
   free(elapsed);
   free(server_backup);
   free(root);
   free(incremental_base);
   free(d);

   pgmoneta_disconnect(client_fd);

   pgmoneta_stop_logging();

   exit(0);

error:

   pgmoneta_management_response_error(NULL, client_fd, config->common.servers[server].name,
                                      ec != -1 ? ec : MANAGEMENT_ERROR_BACKUP_ERROR,
                                      en != NULL ? en : NAME, compression, encryption, payload);

   if (pgmoneta_exists(root))
   {
      pgmoneta_delete_directory(root);
   }
   for (int i = 0; i < number_of_backups; i++)
   {
      free(backups[i]);
   }
   free(temp_backup);
   free(backups);

   pgmoneta_json_destroy(payload);

   pgmoneta_workflow_destroy(workflow);

   pgmoneta_art_destroy(nodes);

   free(date);
   free(backup);
   free(child);
   free(backup_dir);
   free(elapsed);
   free(server_backup);
   free(root);
   free(incremental_base);
   free(d);

   pgmoneta_disconnect(client_fd);

   pgmoneta_stop_logging();

   exit(1);
}

void
pgmoneta_list_backup(int client_fd, int server, uint8_t compression, uint8_t encryption, struct json* payload)
{
   char* d = NULL;
   char* wal_dir = NULL;
   char* elapsed = NULL;
   struct timespec start_t;
   struct timespec end_t;
   double total_seconds;
   char* en = NULL;
   int ec = -1;
   int32_t number_of_backups = 0;
   struct backup** backups = NULL;
   uint64_t wal = 0;
   uint64_t delta = 0;
   struct json* response = NULL;
   struct deque* jl = NULL;
   struct json* j = NULL;
   struct json* bcks = NULL;
   struct deque_iterator* diter = NULL;
   struct main_configuration* config;
   struct json* request = NULL;
   char* sort_order = NULL;
   bool sort_desc = false;
   int comp_result;

   config = (struct main_configuration*)shmem;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &start_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &start_t);
#endif

   if (pgmoneta_deque_create(false, &jl))
   {
      ec = MANAGEMENT_ERROR_LIST_BACKUP_DEQUE_CREATE;
      pgmoneta_log_error("List backup: Error creating the deque for %s", config->common.servers[server].name);
      goto error;
   }

   d = pgmoneta_get_server_backup(server);
   wal_dir = pgmoneta_get_server_wal(server);

   if (pgmoneta_load_infos(d, &number_of_backups, &backups))
   {
      ec = MANAGEMENT_ERROR_LIST_BACKUP_BACKUPS;
      pgmoneta_log_error("List backup: Unable to get backups for %s", config->common.servers[server].name);
      goto error;
   }

   request = (struct json*)pgmoneta_json_get(payload, MANAGEMENT_CATEGORY_REQUEST);
   if (request != NULL)
   {
      sort_order = (char*)pgmoneta_json_get(request, MANAGEMENT_ARGUMENT_SORT);
      if (sort_order != NULL)
      {
         // Only accept valid sort orders: "asc" or "desc"
         if (!strcmp(sort_order, "desc"))
         {
            sort_desc = true;
         }
         else if (!strcmp(sort_order, "asc"))
         {
            sort_desc = false;
         }
         else
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_INVALID_SORT;
            pgmoneta_log_warn("List backup: Invalid sort order '%s', using valid sort orders: \"asc\" or \"desc\"", sort_order);
            goto error;
         }

         // Sort the backups array based on timestamps (label)
         for (int i = 0; i < number_of_backups - 1; i++)
         {
            for (int j = i + 1; j < number_of_backups; j++)
            {
               comp_result = strcmp(backups[i]->label, backups[j]->label);

               // Swap if needed based on sort order
               if ((sort_desc && comp_result < 0) || (!sort_desc && comp_result > 0))
               {
                  struct backup* temp = backups[i];
                  backups[i] = backups[j];
                  backups[j] = temp;
               }
            }
         }
      }
   }

   for (int i = 0; i < number_of_backups; i++)
   {
      if (backups[i] != NULL)
      {
         if (pgmoneta_json_create(&j))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_SERVER, (uintptr_t)config->common.servers[server].name, ValueString))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_BACKUP, (uintptr_t)backups[i]->label, ValueString))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_KEEP, (uintptr_t)backups[i]->keep, ValueBool))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_VALID, (uintptr_t)backups[i]->valid, ValueInt8))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_BACKUP_SIZE, (uintptr_t)backups[i]->backup_size, ValueUInt64))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_RESTORE_SIZE, (uintptr_t)backups[i]->restore_size, ValueUInt64))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_BIGGEST_FILE_SIZE, (uintptr_t)backups[i]->biggest_file_size, ValueUInt64))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_COMPRESSION, (uintptr_t)backups[i]->compression, ValueInt32))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_ENCRYPTION, (uintptr_t)backups[i]->encryption, ValueInt32))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_COMMENTS, (uintptr_t)backups[i]->comments, ValueString))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_INCREMENTAL, (uintptr_t)backups[i]->type, ValueBool))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_INCREMENTAL_PARENT, (uintptr_t)backups[i]->parent_label, ValueString))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         wal = pgmoneta_number_of_wal_files(wal_dir, &backups[i]->wal[0], NULL);
         wal *= config->common.servers[server].wal_size;

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_WAL, (uintptr_t)wal, ValueUInt64))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            pgmoneta_log_error("List backup: Error creating a JSON value for %s", config->common.servers[server].name);
            goto error;
         }

         delta = 0;

         if (i > 0)
         {
            delta = pgmoneta_number_of_wal_files(wal_dir, &backups[i - 1]->wal[0], &backups[i]->wal[0]);
            delta *= config->common.servers[server].wal_size;
         }

         if (pgmoneta_json_put(j, MANAGEMENT_ARGUMENT_WAL, (uintptr_t)delta, ValueUInt64))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            goto error;
         }

         if (pgmoneta_deque_add(jl, NULL, (uintptr_t)j, ValueJSON))
         {
            ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
            goto error;
         }

         j = NULL;
      }
   }

   if (pgmoneta_management_create_response(payload, server, &response))
   {
      ec = MANAGEMENT_ERROR_ALLOCATION;
      goto error;
   }

   if (pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_NUMBER_OF_BACKUPS, (uintptr_t)number_of_backups, ValueUInt32))
   {
      ec = MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE;
      goto error;
   }

   if (pgmoneta_json_create(&bcks))
   {
      goto error;
   }

   if (pgmoneta_deque_iterator_create(jl, &diter))
   {
      goto error;
   }

   while (pgmoneta_deque_iterator_next(diter))
   {
      pgmoneta_json_append(bcks, (uintptr_t)pgmoneta_value_data(diter->value), ValueJSON);
   }

   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_SERVER, (uintptr_t)config->common.servers[server].name, ValueString);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_BACKUPS, (uintptr_t)bcks, ValueJSON);

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &end_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &end_t);
#endif

   if (pgmoneta_management_response_ok(NULL, client_fd, start_t, end_t, compression, encryption, payload))
   {
      ec = MANAGEMENT_ERROR_LIST_BACKUP_NETWORK;
      pgmoneta_log_error("List backup: Error sending response for %s", config->common.servers[server].name);
      goto error;
   }

   elapsed = pgmoneta_get_timestamp_string(start_t, end_t, &total_seconds);
   pgmoneta_log_info("List backup: %s (Elapsed: %s)", config->common.servers[server].name, elapsed);

   pgmoneta_json_destroy(payload);

   for (int i = 0; i < number_of_backups; i++)
   {
      free(backups[i]);
   }
   free(backups);

   free(d);
   free(wal_dir);
   free(elapsed);

   pgmoneta_disconnect(client_fd);

   pgmoneta_stop_logging();

   exit(0);

error:

   pgmoneta_management_response_error(NULL, client_fd, config->common.servers[server].name,
                                      ec != -1 ? ec : MANAGEMENT_ERROR_LIST_BACKUP_ERROR, en != NULL ? en : NAME,
                                      compression, encryption, payload);

   pgmoneta_json_destroy(payload);

   for (int i = 0; i < number_of_backups; i++)
   {
      free(backups[i]);
   }
   free(backups);

   free(d);
   free(wal_dir);
   free(elapsed);

   pgmoneta_disconnect(client_fd);

   pgmoneta_stop_logging();

   exit(1);
}

void
pgmoneta_delete_backup(int client_fd, int srv, uint8_t compression, uint8_t encryption, struct json* payload)
{
   char* identifier = NULL;
   char* elapsed = NULL;
   struct timespec start_t;
   struct timespec end_t;
   double total_seconds;
   int ec = -1;
   char* en = NULL;
   struct json* req = NULL;
   struct json* response = NULL;
   struct workflow* workflow = NULL;
   struct art* nodes = NULL;
   struct backup* backup = NULL;
   struct main_configuration* config;

   pgmoneta_start_logging();

   config = (struct main_configuration*)shmem;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &start_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &start_t);
#endif

   if (pgmoneta_art_create(&nodes))
   {
      goto error;
   }
   req = (struct json*)pgmoneta_json_get(payload, MANAGEMENT_CATEGORY_REQUEST);
   identifier = (char*)pgmoneta_json_get(req, MANAGEMENT_ARGUMENT_BACKUP);
   if (pgmoneta_workflow_nodes(srv, identifier, nodes, &backup))
   {
      goto error;
   }

   workflow = pgmoneta_workflow_create(WORKFLOW_TYPE_DELETE_BACKUP, backup);

   if (pgmoneta_workflow_execute(workflow, nodes, &en, &ec))
   {
      goto error;
   }
   if (pgmoneta_management_create_response(payload, srv, &response))
   {
      ec = MANAGEMENT_ERROR_ALLOCATION;
      goto error;
   }

   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_SERVER, (uintptr_t)config->common.servers[srv].name, ValueString);
   pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_BACKUP, (uintptr_t)pgmoneta_art_search(nodes, NODE_LABEL), ValueString);

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &end_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &end_t);
#endif

   if (pgmoneta_management_response_ok(NULL, client_fd, start_t, end_t, compression, encryption, payload))
   {
      ec = MANAGEMENT_ERROR_DELETE_NETWORK;
      pgmoneta_log_error("Delete: Error sending response for %s", config->common.servers[srv].name);
      goto error;
   }

   elapsed = pgmoneta_get_timestamp_string(start_t, end_t, &total_seconds);

   pgmoneta_log_info("Delete: %s/%s (Elapsed: %s)", config->common.servers[srv].name,
                     (uintptr_t)pgmoneta_art_search(nodes, NODE_LABEL), elapsed);

   free(elapsed);

   pgmoneta_art_destroy(nodes);

   pgmoneta_json_destroy(payload);

   pgmoneta_workflow_destroy(workflow);

   pgmoneta_disconnect(client_fd);

   pgmoneta_stop_logging();

   exit(0);

error:

   pgmoneta_management_response_error(NULL, client_fd, config->common.servers[srv].name,
                                      ec != -1 ? ec : MANAGEMENT_ERROR_DELETE_BACKUP_ERROR, en != NULL ? en : NAME,
                                      compression, encryption, payload);

   pgmoneta_art_destroy(nodes);

   pgmoneta_json_destroy(payload);

   pgmoneta_workflow_destroy(workflow);

   pgmoneta_disconnect(client_fd);

   pgmoneta_stop_logging();

   exit(1);
}

int
pgmoneta_get_backup_max_rate(int server)
{
   struct main_configuration* config;

   config = (struct main_configuration*)shmem;

   if (config->common.servers[server].backup_max_rate != -1)
   {
      return config->common.servers[server].backup_max_rate;
   }

   return config->backup_max_rate;
}

bool
pgmoneta_is_backup_valid(int server, char* identifier)
{
   bool result = false;
   char* d = NULL;
   char* base = NULL;
   char* sha = NULL;
   int number_of_backups = 0;
   struct backup** backups = NULL;
   struct backup* bck = NULL;

   d = pgmoneta_get_server_backup(server);

   if (pgmoneta_load_infos(d, &number_of_backups, &backups))
   {
      goto error;
   }

   if (!strcmp(identifier, "oldest"))
   {
      if (number_of_backups > 0)
      {
         bck = backups[0];
      }
   }
   else if (!strcmp(identifier, "latest") || !strcmp(identifier, "newest"))
   {
      if (number_of_backups > 0)
      {
         bck = backups[number_of_backups - 1];
      }
   }
   else
   {
      /* Explicit search */
      for (int i = 0; i < number_of_backups; i++)
      {
         if (backups[i] != NULL && !strcmp(backups[i]->label, identifier))
         {
            bck = backups[i];
         }
      }
   }

   result = pgmoneta_is_backup_struct_valid(server, bck);

   for (int i = 0; i < number_of_backups; i++)
   {
      free(backups[i]);
   }
   free(backups);

   free(base);
   free(sha);
   free(d);

   return result;

error:

   for (int i = 0; i < number_of_backups; i++)
   {
      free(backups[i]);
   }
   free(backups);

   free(sha);
   free(base);
   free(d);

   return false;
}

bool
pgmoneta_is_backup_struct_valid(int server, struct backup* backup)
{
   bool result = false;
   char* base = NULL;
   char* sha = NULL;
   struct main_configuration* config;

   config = (struct main_configuration*)shmem;

   if (backup != NULL)
   {
      base = pgmoneta_get_server_backup_identifier(server, backup->label);

      if (backup->valid == VALID_TRUE)
      {
         sha = pgmoneta_append(sha, base);
         if (!pgmoneta_ends_with(sha, "/"))
         {
            sha = pgmoneta_append_char(sha, '/');
         }
         sha = pgmoneta_append(sha, "backup.sha512");

         result = pgmoneta_exists(sha);
      }
   }

   if (!result)
   {
      if (backup != NULL)
      {
         backup->valid = VALID_FALSE;
      }

      pgmoneta_log_error("Backup isn't valid: %s/%s",
                         config->common.servers[server].name,
                         backup != NULL ? backup->label : "NULL");
   }

   free(base);
   free(sha);

   return result;
}
