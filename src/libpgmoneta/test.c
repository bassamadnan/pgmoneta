#include <test.h>
#include <stdio.h>
#include <curl/curl.h>
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

int pgmoneta_http_curl_test(void)
{
  printf("Starting CURL test\n");
  CURL *curl;
  CURLcode res;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    printf("Got CURL handle\n");
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "name=daniel&project=curl");
    printf("Performing CURL request\n");
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    else
      printf("CURL request successful\n");
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  printf("ENDING CURL TEST\n\n");
  return 0;
}


static int
build_http_header(int method, const char* hostname, const char* path, char** request, bool keep_alive)
{
   printf("Building HTTP header, method=%d, path=%s\n", method, path);
   char* r = NULL;
   *request = NULL;

   printf("Method comparison: %d vs GET=%d, POST=%d, PUT=%d\n", 
          method, HTTP_GET, HTTP_POST, HTTP_PUT);

   if (method == HTTP_GET) {
      printf("Before GET append\n");
      r = pgmoneta_append(r, "GET ");
      printf("After GET append: %s\n", r ? r : "NULL");
   } else if (method == HTTP_POST) {
      r = pgmoneta_append(r, "POST ");
   } else if (method == HTTP_PUT) {
      r = pgmoneta_append(r, "PUT ");
   } else {
      printf("Invalid HTTP method: %d\n", method);
      return 1;
   }

   r = pgmoneta_append(r, path);
   printf("Added path: %s\n", r);
   
   r = pgmoneta_append(r, " HTTP/1.1\r\n");
   printf("Added HTTP version: %s\n", r);

   r = pgmoneta_append(r, "Host: ");
   r = pgmoneta_append(r, hostname);
   r = pgmoneta_append(r, "\r\n");
   printf("Added host\n");

   r = pgmoneta_append(r, "User-Agent: pgmoneta4/4\r\n");
   printf("Added user agent\n");

   if (method == HTTP_GET) {
      r = pgmoneta_append(r, "Accept: text/*\r\n");
      printf("Added accept header\n");
   }
   
   if(!keep_alive){
      r = pgmoneta_append(r, "Connection: close\r\n");
      printf("Added connection close\n");
   }


   r = pgmoneta_append(r, "\r\n");
   printf("Added end of headers\n");

   *request = r;
   printf("Finished building request headers: %s\n", r);

   return 0;
}

static int
extract_headers_body(char* response, struct http* http)
{
   bool header = true;
   char* p = NULL;
   char* response_copy = NULL;

   if (response == NULL) {
      printf("ERROR: Response is NULL\n");
      return 1;
   }

   response_copy = strdup(response);
   if (response_copy == NULL) {
      printf("ERROR: Failed to duplicate response string\n");
      return 1;
   }

   printf("Tokenizing response\n");
   p = strtok(response_copy, "\n");
   while (p != NULL)
   {
      printf("Processing line: %s\n", p);
      if (*p == '\r')
      {
         printf("Found header/body separator\n");
         header = false;
      }
      else
      {
         if (!pgmoneta_is_number(p, 16))
         {
            if (header)
            {
               printf("Adding to headers: %s\n", p);
               http->headers = pgmoneta_append(http->headers, p);
               http->headers = pgmoneta_append_char(http->headers, '\n');
            }
            else
            {
               printf("Adding to body: %s\n", p);
               http->body = pgmoneta_append(http->body, p);
               http->body = pgmoneta_append_char(http->body, '\n');
            }
         }
         else
         {
            printf("Skipping chunk size line: %s\n", p);
         }
      }

      p = strtok(NULL, "\n");
   }

   free(response_copy);
   printf("Finished extracting headers and body\n");
   return 0;
}

int pgmoneta_http_get(struct http* http, const char* hostname, const char* path)
{
   printf("Starting pgmoneta_http_get\n");
   struct message* msg_request = NULL;
   struct message* msg_response = NULL;
   int error = 0;
   int status;
   char* request = NULL;
   char* response = NULL;
   const char* endpoint = path ? path : "/get";

   printf("Building HTTP header\n");
   if (build_http_header(HTTP_GET, hostname, endpoint, &request, false))
   {
      printf("Failed to build HTTP header\n");
      goto error;
   }

   printf("HTTP request: %s\n", request);
   
   printf("Allocating msg_request\n");
   msg_request = (struct message*)malloc(sizeof(struct message));
   if (msg_request == NULL)
   {
      printf("Failed to allocate msg_request\n");
      goto error;
   }

   memset(msg_request, 0, sizeof(struct message));

   printf("Setting msg_request data\n");
   msg_request->data = request;
   msg_request->length = strlen(request) + 1;

   error = 0;
   printf("Sending request\n");
req:
   if (error < 5)
   {
      printf("Attempt %d to write message on socket: %d\n", error + 1, http->socket);
      status = pgmoneta_write_message(NULL, http->socket, msg_request);
      printf("Write status: %d\n", status);
      if (status != MESSAGE_STATUS_OK)
      {
         error++;
         printf("Write failed, retrying (%d/5)\n", error);
         goto req;
      }
   }
   else
   {
      printf("Failed to write after 5 attempts\n");
      goto error;
   }

   printf("Request sent successfully, reading response\n");
   response = NULL;

   status = pgmoneta_read_block_message(NULL, http->socket, &msg_response);
   printf("Read status: %d, msg_response pointer = %p\n", status, (void*)msg_response);
   
   if (status == MESSAGE_STATUS_OK && msg_response && msg_response->data)
   {
      printf("Got message, appending to response\n");
      printf("Message data: %s\n", (char*)msg_response->data);
      response = pgmoneta_append(response, (char*)msg_response->data);
      printf("Response after append: %s\n", response);
   }

   printf("Finished reading response blocks\n");
   
   if (response == NULL) {
      printf("ERROR: No response data collected\n");
      goto error;
   }
   
   printf("Full response: %s\n", response);

   printf("Extracting headers and body\n");
   if (extract_headers_body(response, http))
   {
      printf("Failed to extract headers and body\n");
      goto error;
   }

   printf("HTTP Headers:\n%s\n", http->headers ? http->headers : "NULL");
   printf("HTTP Body:\n%s\n", http->body ? http->body : "NULL");

   printf("Freeing resources\n");
   free(request);
   free(response);
   free(msg_request);
   if (msg_response)
      pgmoneta_free_message(msg_response);

   printf("Finished pgmoneta_http_get successfully\n");
   return 0;

error:
   printf("Error in pgmoneta_http_get, cleaning up\n");
   if (request) free(request);
   if (response) free(response);
   if (msg_request) free(msg_request);
   if (msg_response) pgmoneta_free_message(msg_response);

   printf("Finished error cleanup\n");
   return 1;
}

int pgmoneta_http_test(void)
{
    printf("Starting pgmoneta_http_test\n");
    int status;
    struct http* h = NULL;
    
    printf("Allocating http structure\n");
    h = (struct http*) malloc(sizeof(struct http));
    if(h == NULL)
    {
        pgmoneta_log_error("Failed to allocate to HTTP");
        printf("Failed to allocate HTTP structure\n");
        return 1;
    }
    
    printf("Initializing http structure\n");
    memset(h, 0, sizeof(struct http));
    
    const char* hostname = "postman-echo.com";
    printf("Connecting to %s:80\n", hostname);
    if (pgmoneta_connect(hostname, 80, &h->socket))
    {
       pgmoneta_log_error("Failed to connect to %s:%d", hostname, 80);
       printf("Failed to connect to %s:80\n", hostname);
       free(h);
       return 1;
    }
    printf("Connected, socket: %d\n", h->socket);

    printf("Calling pgmoneta_http_get\n");
    status = pgmoneta_http_get(h, hostname, "/get");
    printf("pgmoneta_http_get returned: %d\n", status);

    printf("Disconnecting socket\n");
    pgmoneta_disconnect(h->socket);
    
    printf("Freeing http structure\n");
    if (h->headers != NULL)
        free(h->headers);
    if (h->body != NULL)
        free(h->body);
    
    free(h);
    
    printf("Finished pgmoneta_http_test\n");
    return 0;
}