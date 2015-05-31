
#ifndef _HTTP_H_
#define _HTTP_H_


#include "Utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <curl/curl.h>
#include <map>
#include <vector>


using namespace std;

namespace OAuth2CPP {

	namespace Core {

		typedef enum OAUTH2CPP_API
		{
			M_GET = 0,
			M_POST,
			M_PUT,
			M_DELETE,
		} HttpMethod;

		typedef struct OAUTH2CPP_API CurlCTX
		{
			CURL* curl = NULL;
			char* memory = NULL;
			size_t size;
			curl_slist* headers = NULL;
		} CurlCTX;


		typedef struct OAUTH2CPP_API HttpResult {
			string url;
			long statusCode;
			CURLcode curlStatus;
			char* curlErrorMsg = NULL;
			CurlCTX* ctx = NULL;

			bool IsCurlOK()
			{
				return(this->curlStatus == CURLE_OK
					&& this->ctx != NULL);
			}

			bool IsCurlResponseOK()
			{
				return(this->IsCurlOK()
					&& this->ctx->memory != NULL);
			}
		} HttpResult;




		class OAUTH2CPP_API HttpParameters {
		private:
			std::map<string, string> *params = NULL;
			string url;
			//CurlCTX* ctx = NULL;
			CURL* curl = NULL;
			bool uCurl = false;

		private:
			void checkParamsMap(void);

		public:
			HttpParameters() {};
			HttpParameters(c_string_ref url);
			~HttpParameters();

			void Add(c_string_ref key, c_string_ref param);
			void Add(c_char_ptr key, c_string_ref param);
			void Add(c_char_ptr key, c_char_ptr param);
			void SetUrl(c_string_ref url);
			//void SetCTX(CurlCTX *ctx);
			void SetCURL(CURL* curl);

			string toStr();

		};

		typedef OAUTH2CPP_API HttpParameters HttpURL;




		class OAUTH2CPP_API HttpBody {
		protected:
			~HttpBody()  {};

		public:
			virtual bool IsChunked() = 0;
			virtual bool HasSize() = 0;
			virtual long Size() = 0;
			virtual void Prepare(CurlCTX *ctx = NULL) { (void)ctx; };
			virtual size_t ReadCallback(void *ptr, size_t size, size_t nmemb) = 0;
		};

		class OAUTH2CPP_API EmptyHttpBody : virtual public HttpBody
		{
		public:
			bool IsChunked() { return false; }
			bool HasSize() { return true; }
			long Size() { return 0; };

			size_t ReadCallback(void *ptr, size_t size, size_t nmemb) {
				(void)ptr; (void)size; (void)nmemb;
				return 0;
			}
		};

		class OAUTH2CPP_API FileHttpBody : virtual public HttpBody
		{
		private:
			bool hasSize;
			bool chunked;
			bool hasRead;
			long size;
			FILE* stream = NULL;
		public:
			FileHttpBody(FILE* stream, bool chunked = false, bool hasSize = false);

			bool IsChunked();
			bool HasSize();
			long Size();
			size_t ReadCallback(void *ptr, size_t size, size_t nmemb);
		};


		class OAUTH2CPP_API URLEncodedHttpBody : virtual public HttpBody
		{
		private:
			long size;
			char* data = NULL;
			string tmpData;
			size_t readPtr;
			HttpParameters params;
		public:
			URLEncodedHttpBody();
			~URLEncodedHttpBody();

			void Add(c_string_ref key, c_string_ref value);
			void Add(c_char_ptr key, c_string_ref value);
			void Add(c_char_ptr key, c_char_ptr value);

			void Prepare(CurlCTX *ctx = NULL);

			bool IsChunked();
			bool HasSize();
			long Size();
			size_t ReadCallback(void *ptr, size_t size, size_t nmemb);
		};



		class OAUTH2CPP_API Http final {

		private:
			static bool debug;

		public:
			static string USER_AGENT;

		private:
			Http() {};
			Http(const Http&) = delete;
			Http& operator=(const Http&) = delete;

		public:
			~Http() {};

		private:
			HttpResult* Request(HttpURL *url, c_string* urlStr, HttpMethod method, HttpBody *body = NULL, vector<string> *headers = NULL);

		public:

			//HttpResult* Get(HttpURL* url);
			//HttpResult* Delete(HttpURL* url, HttpBody *body = NULL);
			//HttpResult* Put(HttpURL* url, HttpBody *body = NULL);
			//HttpResult* Post(HttpURL* url, HttpBody *body = NULL);

			HttpResult* Request(HttpURL *url, HttpMethod method, HttpBody *body = NULL, vector<string> *headers = NULL);
			HttpResult* Request(c_string* url, HttpMethod method, HttpBody *body = NULL, vector<string> *headers = NULL);



			static void Init(void);
			static void Terminate(void);

			static void SetDebug(bool debug);
			static void SetUserAgent(string userAgent);

			static Http* GetInstance(void);

			static void ReleaseHttpResult(HttpResult* result);
		};

	}
}

#endif /* _HTTP_H_ */