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

   if (pgmoneta_http_connect((char*)hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      return 1;
   }

   printf("Calling pgmoneta_http_get\n");
   status = pgmoneta_http_get(h, (char*)hostname, "/get");
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

   if (pgmoneta_http_connect((char*)hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      return 1;
   }

   printf("Calling pgmoneta_http_get\n");
   status = pgmoneta_http_get(h, (char*)hostname, "/get");
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

   if (pgmoneta_http_connect((char*)hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      return 1;
   }

   printf("Calling pgmoneta_http_post\n");
   status = pgmoneta_http_post(h, (char*)hostname, "/post", (char*)test_data, strlen(test_data));
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

   if (pgmoneta_http_connect((char*)hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      return 1;
   }

   printf("Calling pgmoneta_http_put\n");
   status = pgmoneta_http_put(h, (char*)hostname, "/put", (void*)test_data, strlen(test_data));
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

   if (pgmoneta_http_connect((char*)hostname, port, secure, &h))
   {
      printf("Failed to connect to %s:%d\n", hostname, port);
      fclose(temp_file);
      return 1;
   }

   printf("Calling pgmoneta_http_put_file\n");
   status = pgmoneta_http_put_file(h, (char*)hostname, "/put", temp_file, data_len, "text/plain");
   printf("pgmoneta_http_put_file returned: %d\n", status);

   pgmoneta_http_disconnect(h);
   free(h);
   fclose(temp_file);

   printf("Finished pgmoneta_http_put_file_test\n");
   return 0;
}
