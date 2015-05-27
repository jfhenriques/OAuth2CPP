
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
		CurlCTX* ctx = NULL;

	private:
		void checkParamsMap(void);

	public:
		HttpParameters() {};
		HttpParameters(const string &url);
		~HttpParameters();

		void Add(const string &key, const string &param);
		void Add(const char *key, const string &param);
		void Add(const char *key, const char *param);
		void SetUrl(const string &url);
		void SetCTX(CurlCTX *ctx);

		string toStr();

	};

	typedef OAUTH2CPP_API HttpParameters HttpURL;




	class OAUTH2CPP_API HttpBody {
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

		void AddParam(const string &key, const string &value);
		void Prepare(CurlCTX *ctx = NULL);

		bool IsChunked();
		bool HasSize();
		long Size();
		size_t ReadCallback(void *ptr, size_t size, size_t nmemb);
	};



	class OAUTH2CPP_API Http {

	private:
		static bool debug;

	public:
		static string USER_AGENT;
		
		Http() {};
		~Http() {};

		void releaseResult(HttpResult* result);
		HttpResult* Request(HttpURL* url, HttpMethod method, HttpBody *body = NULL, vector<string> *headers = NULL);

		HttpResult* Get(HttpURL* url);
		HttpResult* Delete(HttpURL* url, HttpBody *body = NULL);
		HttpResult* Put(HttpURL* url, HttpBody *body = NULL);
		HttpResult* Post(HttpURL* url, HttpBody *body = NULL);

		static void Init(void);
		static void Terminate(void);

		static void SetDebug(bool debug);

	};


}

#endif /* _HTTP_H_ */