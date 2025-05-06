#include <test.h>
#include <stdio.h>
#include <pgmoneta.h>
#include <logging.h>
#include <network.h>
#include <security.h>
#include <http.h>
#include <message.h>
#include <utils.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <openssl/ssl.h>

int
pgmoneta_http_test(void)
{
   printf("Starting pgmoneta_http_test\n");
   int status;
   struct http* h = NULL;

   const char* hostname = "postman-echo.com";
   int port = 80;
   bool secure = false;

   if (pgmoneta_http_connect(hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      return 1;
   }

   printf("Calling pgmoneta_http_get\n");
   status = pgmoneta_http_get(h, hostname, "/get");
   printf("pgmoneta_http_get returned: %d\n", status);
   
   if (status == 0)
   {
      printf("\nResponse Headers:\n%s\n", h->headers ? h->headers : "None");
      printf("\nResponse Body:\n%s\n", h->body ? h->body : "None");
   }
   else
   {
      printf("Request failed, no response to display\n");
   }

   pgmoneta_http_disconnect(h);
   free(h);

   printf("Finished pgmoneta_http_test\n");
   return 0;
}

int
pgmoneta_https_test(void)
{
   printf("Starting pgmoneta_https_test\n");
   int status;
   struct http* h = NULL;

   const char* hostname = "postman-echo.com";
   int port = 443;
   bool secure = true;

   if (pgmoneta_http_connect(hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      return 1;
   }

   printf("Calling pgmoneta_http_get\n");
   status = pgmoneta_http_get(h, hostname, "/get");
   printf("pgmoneta_http_get returned: %d\n", status);

   if (status == 0)
   {
      printf("\nResponse Headers:\n%s\n", h->headers ? h->headers : "None");
      printf("\nResponse Body:\n%s\n", h->body ? h->body : "None");
   }
   else
   {
      printf("Request failed, no response to display\n");
   }

   pgmoneta_http_disconnect(h);
   free(h);

   printf("Finished pgmoneta_https_test\n");
   return 0;
}

int
pgmoneta_http_post_test(void)
{
   printf("Starting pgmoneta_http_post_test\n");
   int status;
   struct http* h = NULL;

   const char* hostname = "postman-echo.com";
   int port = 443;
   bool secure = true;
   const char* test_data = "name=pgmoneta&version=1.0";

   if (pgmoneta_http_connect(hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      return 1;
   }

   printf("Calling pgmoneta_http_post\n");
   status = pgmoneta_http_post(h, hostname, "/post", test_data, strlen(test_data));
   printf("pgmoneta_http_post returned: %d\n", status);

   pgmoneta_http_disconnect(h);
   free(h);

   printf("Finished pgmoneta_http_post_test\n");
   return 0;
}

int
pgmoneta_http_put_test(void)
{
   printf("Starting pgmoneta_http_put_test\n");
   int status;
   struct http* h = NULL;

   const char* hostname = "postman-echo.com";
   int port = 443;
   bool secure = true;
   const char* test_data = "This is a test file content for PUT request";

   if (pgmoneta_http_connect(hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      return 1;
   }

   printf("Calling pgmoneta_http_put\n");
   status = pgmoneta_http_put(h, hostname, "/put", test_data, strlen(test_data));
   printf("pgmoneta_http_put returned: %d\n", status);

   pgmoneta_http_disconnect(h);
   free(h);

   printf("Finished pgmoneta_http_put_test\n");
   return 0;
}

int
pgmoneta_http_put_file_test(void)
{
   printf("Starting pgmoneta_http_put_file_test\n");
   int status;
   struct http* h = NULL;
   FILE* temp_file = NULL;

   const char* hostname = "postman-echo.com";
   int port = 443;
   bool secure = true;
   const char* test_data = "This is a test file content for PUT file request\nSecond line of test data\nThird line with some numbers: 12345";
   size_t data_len = strlen(test_data);

   temp_file = tmpfile();
   if (temp_file == NULL)
   {
      printf("Failed to create temporary file\n");
      return 1;
   }

   if (fwrite(test_data, 1, data_len, temp_file) != data_len)
   {
      printf("Failed to write to temporary file\n");
      fclose(temp_file);
      return 1;
   }

   rewind(temp_file);

   if (pgmoneta_http_connect(hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      fclose(temp_file);
      return 1;
   }

   printf("Calling pgmoneta_http_put_file\n");
   status = pgmoneta_http_put_file(h, hostname, "/put", temp_file, data_len, "text/plain");
   printf("pgmoneta_http_put_file returned: %d\n", status);

   pgmoneta_http_disconnect(h);
   free(h);
   fclose(temp_file);

   printf("Finished pgmoneta_http_put_file_test\n");
   return 0;
}

int
pgmoneta_s3_upload_test(void)
{
   printf("Starting pgmoneta_s3_test\n");

   struct main_configuration* config;
   config = (struct main_configuration*)shmem;

   const char* s3_aws_region = config->s3_aws_region;
   const char* s3_access_key_id = config->s3_access_key_id;
   const char* s3_secret_access_key = config->s3_secret_access_key;
   const char* s3_bucket = config->s3_bucket;
   const char* s3_base_dir = config->s3_base_dir;

   char* temp_filename = "/tmp/pgmoneta_s3_test_file.txt";
   const char* test_content = "This is a test file for pgMoneta S3 upload functionality.\n"
                              "This file was created for testing the custom HTTP implementation.\n"
                              "The timestamp is: ";

   FILE* test_file = fopen(temp_filename, "w");
   if (test_file == NULL)
   {
      printf("Failed to create test file\n");
      return 1;
   }

   fputs(test_content, test_file);

   time_t now = time(NULL);
   char time_str[64];
   strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
   fputs(time_str, test_file);

   fclose(test_file);

   struct stat file_stat;
   if (stat(temp_filename, &file_stat) != 0)
   {
      printf("Failed to get file stats\n");
      return 1;
   }
   size_t file_size = file_stat.st_size;
   printf("Test file created with size: %zu bytes\n", file_size);

   test_file = fopen(temp_filename, "rb");
   if (test_file == NULL)
   {
      printf("Failed to open test file for reading\n");
      return 1;
   }

   char object_key[256];
   sprintf(object_key, "%s/test_%ld.txt", s3_base_dir, (long)now);
   printf("S3 object key: %s\n", object_key);

   struct http* h = NULL;
   char short_date[SHORT_TIME_LENGTH];
   char long_date[LONG_TIME_LENGTH];
   char* file_sha256 = NULL;
   char* s3_host = NULL;
   char* canonical_request = NULL;
   char* string_to_sign = NULL;
   char* auth_value = NULL;
   char* canonical_request_sha256 = NULL;

   memset(&short_date[0], 0, sizeof(short_date));
   memset(&long_date[0], 0, sizeof(long_date));

   if (pgmoneta_get_timestamp_ISO8601_format(short_date, long_date))
   {
      printf("Failed to get timestamp\n");
      fclose(test_file);
      return 1;
   }

   printf("Short date: %s\n", short_date);
   printf("Long date: %s\n", long_date);

   pgmoneta_create_sha256_file(temp_filename, &file_sha256);
   printf("File SHA256: %s\n", file_sha256);

   s3_host = malloc(strlen(s3_bucket) + strlen(s3_aws_region) + 20);
   sprintf(s3_host, "%s.s3.%s.amazonaws.com", s3_bucket, s3_aws_region);
   printf("S3 host: %s\n", s3_host);

   if (pgmoneta_http_connect(s3_host, 443, true, &h))
   {
      printf("Failed to connect to S3\n");
      fclose(test_file);
      free(s3_host);
      free(file_sha256);
      return 1;
   }

   canonical_request = pgmoneta_append(canonical_request, "PUT\n/");
   canonical_request = pgmoneta_append(canonical_request, object_key);
   canonical_request = pgmoneta_append(canonical_request, "\n\nhost:");
   canonical_request = pgmoneta_append(canonical_request, s3_host);
   canonical_request = pgmoneta_append(canonical_request, "\nx-amz-content-sha256:");
   canonical_request = pgmoneta_append(canonical_request, file_sha256);
   canonical_request = pgmoneta_append(canonical_request, "\nx-amz-date:");
   canonical_request = pgmoneta_append(canonical_request, long_date);
   canonical_request = pgmoneta_append(canonical_request, "\nx-amz-storage-class:REDUCED_REDUNDANCY\n\nhost;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n");
   canonical_request = pgmoneta_append(canonical_request, file_sha256);

   pgmoneta_generate_string_sha256_hash(canonical_request, &canonical_request_sha256);
   printf("Canonical request hash: %s\n", canonical_request_sha256);

   string_to_sign = pgmoneta_append(string_to_sign, "AWS4-HMAC-SHA256\n");
   string_to_sign = pgmoneta_append(string_to_sign, long_date);
   string_to_sign = pgmoneta_append(string_to_sign, "\n");
   string_to_sign = pgmoneta_append(string_to_sign, short_date);
   string_to_sign = pgmoneta_append(string_to_sign, "/");
   string_to_sign = pgmoneta_append(string_to_sign, s3_aws_region);
   string_to_sign = pgmoneta_append(string_to_sign, "/s3/aws4_request\n");
   string_to_sign = pgmoneta_append(string_to_sign, canonical_request_sha256);

   char* key = NULL;
   unsigned char* date_key_hmac = NULL;
   unsigned char* date_region_key_hmac = NULL;
   unsigned char* date_region_service_key_hmac = NULL;
   unsigned char* signing_key_hmac = NULL;
   unsigned char* signature_hmac = NULL;
   unsigned char* signature_hex = NULL;
   int hmac_length = 0;

   key = pgmoneta_append(key, "AWS4");
   key = pgmoneta_append(key, s3_secret_access_key);

   if (pgmoneta_generate_string_hmac_sha256_hash(key, strlen(key), short_date, SHORT_TIME_LENGTH - 1,
                                                 &date_key_hmac, &hmac_length))
   {
      printf("Failed to generate date key\n");
      goto error;
   }

   if (pgmoneta_generate_string_hmac_sha256_hash((char*)date_key_hmac, hmac_length, s3_aws_region,
                                                 strlen(s3_aws_region), &date_region_key_hmac, &hmac_length))
   {
      printf("Failed to generate date-region key\n");
      goto error;
   }

   if (pgmoneta_generate_string_hmac_sha256_hash((char*)date_region_key_hmac, hmac_length, "s3",
                                                 strlen("s3"), &date_region_service_key_hmac, &hmac_length))
   {
      printf("Failed to generate date-region-service key\n");
      goto error;
   }

   if (pgmoneta_generate_string_hmac_sha256_hash((char*)date_region_service_key_hmac, hmac_length,
                                                 "aws4_request", strlen("aws4_request"),
                                                 &signing_key_hmac, &hmac_length))
   {
      printf("Failed to generate signing key\n");
      goto error;
   }

   printf("Generated signing key\n");

   if (pgmoneta_generate_string_hmac_sha256_hash((char*)signing_key_hmac, hmac_length, string_to_sign,
                                                 strlen(string_to_sign), &signature_hmac, &hmac_length))
   {
      printf("Failed to generate signature\n");
      goto error;
   }

   pgmoneta_convert_base32_to_hex(signature_hmac, hmac_length, &signature_hex);
   printf("Signature: %s\n", signature_hex);

   auth_value = pgmoneta_append(auth_value, "AWS4-HMAC-SHA256 Credential=");
   auth_value = pgmoneta_append(auth_value, s3_access_key_id);
   auth_value = pgmoneta_append(auth_value, "/");
   auth_value = pgmoneta_append(auth_value, short_date);
   auth_value = pgmoneta_append(auth_value, "/");
   auth_value = pgmoneta_append(auth_value, s3_aws_region);
   auth_value = pgmoneta_append(auth_value, "/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=");
   auth_value = pgmoneta_append(auth_value, (char*)signature_hex);

   printf("Authorization header generated\n");

   pgmoneta_http_add_header(h, "Authorization", auth_value);
   pgmoneta_http_add_header(h, "x-amz-content-sha256", file_sha256);
   pgmoneta_http_add_header(h, "x-amz-date", long_date);
   pgmoneta_http_add_header(h, "x-amz-storage-class", "REDUCED_REDUNDANCY");

   char s3_path[512];
   sprintf(s3_path, "/%s", object_key);
   printf("S3 path for HTTP PUT: %s\n", s3_path);

   printf("Uploading file to S3...\n");
   int result = pgmoneta_http_put_file(h, s3_host, s3_path, test_file, file_size, "application/octet-stream");

   if (result == 0)
   {
      printf("File uploaded successfully to S3\n");
      printf("Object URL: https://%s/%s\n", s3_host, object_key);
   }
   else
   {
      printf("Failed to upload file to S3\n");
   }

   fclose(test_file);
   pgmoneta_http_disconnect(h);
   free(h);
   free(s3_host);
   free(file_sha256);
   free(canonical_request);
   free(canonical_request_sha256);
   free(string_to_sign);
   free(key);
   if (date_key_hmac)
   {
      free(date_key_hmac);
   }
   if (date_region_key_hmac)
   {
      free(date_region_key_hmac);
   }
   if (date_region_service_key_hmac)
   {
      free(date_region_service_key_hmac);
   }
   if (signing_key_hmac)
   {
      free(signing_key_hmac);
   }
   if (signature_hmac)
   {
      free(signature_hmac);
   }
   if (signature_hex)
   {
      free(signature_hex);
   }
   if (auth_value)
   {
      free(auth_value);
   }

   remove(temp_filename);

   printf("Finished pgmoneta_s3_test\n");
   return result;

error:
   if (test_file)
   {
      fclose(test_file);
   }
   if (h)
   {
      pgmoneta_http_disconnect(h);
      free(h);
   }
   if (s3_host)
   {
      free(s3_host);
   }
   if (file_sha256)
   {
      free(file_sha256);
   }
   if (canonical_request)
   {
      free(canonical_request);
   }
   if (canonical_request_sha256)
   {
      free(canonical_request_sha256);
   }
   if (string_to_sign)
   {
      free(string_to_sign);
   }
   if (key)
   {
      free(key);
   }
   if (date_key_hmac)
   {
      free(date_key_hmac);
   }
   if (date_region_key_hmac)
   {
      free(date_region_key_hmac);
   }
   if (date_region_service_key_hmac)
   {
      free(date_region_service_key_hmac);
   }
   if (signing_key_hmac)
   {
      free(signing_key_hmac);
   }
   if (signature_hmac)
   {
      free(signature_hmac);
   }
   if (signature_hex)
   {
      free(signature_hex);
   }
   if (auth_value)
   {
      free(auth_value);
   }

   remove(temp_filename);

   printf("Failed pgmoneta_s3_test with error\n");
   return 1;
}

int
pgmoneta_azure_upload_test(void)
{
   printf("Starting pgmoneta_azure_test\n");

   struct main_configuration* config;
   config = (struct main_configuration*)shmem;

   // Get configuration values from config
   const char* azure_storage_account = config->azure_storage_account;
   const char* azure_container = config->azure_container;
   const char* azure_shared_key = config->azure_shared_key;
   const char* azure_base_dir = config->azure_base_dir;

   // Create test file
   char* temp_filename = "/tmp/pgmoneta_azure_test_file.txt";
   const char* test_content = "This is a test file for pgMoneta Azure upload functionality.\n"
                              "This file was created for testing the custom HTTP implementation.\n"
                              "The timestamp is: ";

   FILE* test_file = fopen(temp_filename, "w");
   if (test_file == NULL)
   {
      printf("Failed to create test file\n");
      return 1;
   }

   fputs(test_content, test_file);

   time_t now = time(NULL);
   char time_str[64];
   strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
   fputs(time_str, test_file);

   fclose(test_file);

   struct stat file_stat;
   if (stat(temp_filename, &file_stat) != 0)
   {
      printf("Failed to get file stats\n");
      return 1;
   }
   size_t file_size = file_stat.st_size;
   printf("Test file created with size: %zu bytes\n", file_size);

   test_file = fopen(temp_filename, "rb");
   if (test_file == NULL)
   {
      printf("Failed to open test file for reading\n");
      return 1;
   }

   // Create a unique blob path for the test
   char blob_path[256];
   sprintf(blob_path, "%s/test_%ld.txt", azure_base_dir, (long)now);
   printf("Azure blob path: %s\n", blob_path);

   // Get UTC timestamp in the format Azure expects
   char utc_date[64];
   memset(&utc_date[0], 0, sizeof(utc_date));

   // Use the same function as in the working implementation
   if (pgmoneta_get_timestamp_UTC_format(utc_date))
   {
      printf("Failed to get UTC timestamp\n");
      goto error;
   }
   printf("UTC date: %s\n", utc_date);

   // Construct string to sign exactly like in the working implementation
   char* string_to_sign = NULL;

   // Different handling for zero-size files
   if (file_size == 0)
   {
      string_to_sign = pgmoneta_append(string_to_sign, "PUT\n\n\n\n\napplication/octet-stream\n\n\n\n\n\n\nx-ms-blob-type:BlockBlob\nx-ms-date:");
   }
   else
   {
      string_to_sign = pgmoneta_append(string_to_sign, "PUT\n\n\n");
      char size_str[32];
      snprintf(size_str, sizeof(size_str), "%zu", file_size);
      string_to_sign = pgmoneta_append(string_to_sign, size_str);
      string_to_sign = pgmoneta_append(string_to_sign, "\n\napplication/octet-stream\n\n\n\n\n\n\nx-ms-blob-type:BlockBlob\nx-ms-date:");
   }

   string_to_sign = pgmoneta_append(string_to_sign, utc_date);
   string_to_sign = pgmoneta_append(string_to_sign, "\nx-ms-version:2021-08-06\n/");
   string_to_sign = pgmoneta_append(string_to_sign, azure_storage_account);
   string_to_sign = pgmoneta_append(string_to_sign, "/");
   string_to_sign = pgmoneta_append(string_to_sign, azure_container);
   string_to_sign = pgmoneta_append(string_to_sign, "/");
   string_to_sign = pgmoneta_append(string_to_sign, blob_path);

   printf("String to sign:\n%s\n", string_to_sign);

   // Decode the shared key (base64)
   char* signing_key = NULL;
   size_t signing_key_length = 0;
   pgmoneta_base64_decode(azure_shared_key, strlen(azure_shared_key), (void**)&signing_key, &signing_key_length);
   printf("Decoded shared key length: %zu bytes\n", signing_key_length);

   // Create HMAC signature
   unsigned char* signature_hmac = NULL;
   int hmac_length = 0;
   if (pgmoneta_generate_string_hmac_sha256_hash(signing_key, signing_key_length,
                                                 string_to_sign, strlen(string_to_sign),
                                                 &signature_hmac, &hmac_length))
   {
      printf("Failed to generate HMAC signature\n");
      goto error;
   }
   printf("Generated HMAC signature (%d bytes)\n", hmac_length);

   // Encode the signature (base64)
   char* base64_signature = NULL;
   size_t base64_signature_length = 0;
   pgmoneta_base64_encode((char*)signature_hmac, hmac_length, &base64_signature, &base64_signature_length);
   printf("Base64 signature: %s\n", base64_signature);

   // Create authorization header
   char* auth_value = NULL;
   auth_value = pgmoneta_append(auth_value, "SharedKey ");
   auth_value = pgmoneta_append(auth_value, azure_storage_account);
   auth_value = pgmoneta_append(auth_value, ":");
   auth_value = pgmoneta_append(auth_value, base64_signature);
   printf("Authorization header created\n");

   // Get the host - use same function as the working implementation
   char* azure_host = NULL;
   azure_host = pgmoneta_append(azure_host, azure_storage_account);
   azure_host = pgmoneta_append(azure_host, ".blob.core.windows.net");
   printf("Azure host: %s\n", azure_host);

   // Create URL
   char* azure_url = NULL;
   azure_url = pgmoneta_append(azure_url, "https://");
   azure_url = pgmoneta_append(azure_url, azure_host);
   azure_url = pgmoneta_append(azure_url, "/");
   azure_url = pgmoneta_append(azure_url, azure_container);
   azure_url = pgmoneta_append(azure_url, "/");
   azure_url = pgmoneta_append(azure_url, blob_path);
   printf("Azure URL: %s\n", azure_url);

   // Create HTTP connection
   struct http* http = NULL;
   if (pgmoneta_http_connect(azure_host, 443, true, &http))
   {
      printf("Failed to connect to Azure: %s\n", azure_host);
      goto error;
   }
   printf("Connected to Azure\n");

   // Add headers in the same order as the working implementation
   pgmoneta_http_add_header(http, "Authorization", auth_value);
   pgmoneta_http_add_header(http, "x-ms-blob-type", "BlockBlob");
   pgmoneta_http_add_header(http, "x-ms-date", utc_date);
   pgmoneta_http_add_header(http, "x-ms-version", "2021-08-06");
   printf("Added headers\n");

   // Create PUT path
   char azure_put_path[512];
   sprintf(azure_put_path, "/%s/%s", azure_container, blob_path);
   printf("Azure PUT path: %s\n", azure_put_path);

   // Send PUT request with file
   printf("Uploading file to Azure...\n");
   int result = pgmoneta_http_put_file(http, azure_host, azure_put_path, test_file, file_size, "application/octet-stream");

   if (result == 0)
   {
      printf("File uploaded successfully to Azure\n");
      printf("Blob URL: %s\n", azure_url);
   }
   else
   {
      printf("Failed to upload file to Azure\n");
   }

   // Clean up
   fclose(test_file);
   pgmoneta_http_disconnect(http);
   free(http);
   free(azure_host);
   free(azure_url);
   free(string_to_sign);
   free(signing_key);
   free(signature_hmac);
   free(base64_signature);
   free(auth_value);

   remove(temp_filename);

   printf("Finished pgmoneta_azure_test\n");
   return result;

error:
   if (test_file)
   {
      fclose(test_file);
   }
   if (http)
   {
      pgmoneta_http_disconnect(http);
      free(http);
   }
   if (azure_host)
   {
      free(azure_host);
   }
   if (azure_url)
   {
      free(azure_url);
   }
   if (string_to_sign)
   {
      free(string_to_sign);
   }
   if (signing_key)
   {
      free(signing_key);
   }
   if (signature_hmac)
   {
      free(signature_hmac);
   }
   if (base64_signature)
   {
      free(base64_signature);
   }
   if (auth_value)
   {
      free(auth_value);
   }

   remove(temp_filename);

   printf("Failed pgmoneta_azure_test with error\n");
   return 1;
}