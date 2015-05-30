
#include "Http.h"
#include "Utils.h"
#include <iostream>
#include <stdlib.h>
#include <vector>
#include <sstream>

using namespace std;

namespace OAuth2CPP {
	namespace Core {

		/********************************************************************************************
		*
		*	HttpParameters
		*
		********************************************************************************************/


		HttpParameters::HttpParameters(c_string_ref url)
		{
			this->url = url;
		}

		HttpParameters::~HttpParameters()
		{
			if (this->params != NULL)
				delete this->params;
		}


		void HttpParameters::checkParamsMap(void)
		{
			if (this->params == NULL)
				this->params = new std::map<string, string>();
		}

		void HttpParameters::Add(c_string_ref key, c_string_ref param)
		{
			this->checkParamsMap();

			this->params->insert(std::pair<string, string>(key, param));
		}
		void HttpParameters::Add(c_char_ptr key, c_string_ref param)
		{
			this->checkParamsMap();

			this->params->insert(std::pair<string, string>(key, param));
		}
		void HttpParameters::Add(c_char_ptr key, c_char_ptr param)
		{
			this->checkParamsMap();

			this->params->insert(this->params->end(), std::pair<string, string>(key, param));
		}


		void HttpParameters::SetUrl(c_string_ref url)
		{
			this->url = url;
		}
		void HttpParameters::SetCTX(CurlCTX *ctx)
		{
			this->ctx = ctx;
		}

		string HttpParameters::toStr()
		{
			if (this->params == NULL || this->params->size() <= 0)
				return this->url;

			bool hadCurl;
			CURL *curlPtr = NULL;
			char *tmp;

			vector<char*> escList;
			stringstream ss;
			bool isFirst = true;
			string outStr;

			if (this->ctx != NULL && this->ctx->curl != NULL)
			{
				hadCurl = true;
				curlPtr = this->ctx->curl;
			}
			else
			{
				hadCurl = false;
				curlPtr = curl_easy_init();

				if (!curlPtr)
					throw OAUTH2CPP_ERROR_HTTP;
			}

			if (!this->url.empty())
				ss << this->url << "?";

			// build it

			for (map<string, string>::iterator it = this->params->begin(); it != this->params->end(); it++)
			{
				if (it->first.length() == 0) continue;

				// Key
				tmp = curl_easy_escape(curlPtr, it->first.c_str(), 0);
				if (tmp == NULL) continue;

				escList.push_back(tmp);

				if (isFirst)
					isFirst = false;

				else
					ss << "&";

				ss << (string)tmp;


				// value

				if (it->second.length() == 0) continue;

				tmp = curl_easy_escape(curlPtr, it->second.c_str(), 0);
				if (tmp == NULL) continue;

				escList.push_back(tmp);

				ss << "=" << (string)tmp;
			}

			outStr = ss.str();

			// cleanup
			for (vector<char*>::iterator it = escList.begin(); it != escList.end(); it++)
			{
				curl_free(*it);
			}

			if (!hadCurl)
				curl_easy_cleanup(curlPtr);

			return outStr;
		}





		/********************************************************************************************
		*
		*	FileHttpBody
		*
		********************************************************************************************/



		FileHttpBody::FileHttpBody(FILE *stream, bool chunked, bool hasSize)
		{
			this->hasSize = hasSize;
			this->stream = stream;
			this->size = 0L;
			this->chunked = chunked;

			if (hasSize)
			{
				fseek(this->stream, 0, SEEK_END);
				this->size = ftell(this->stream);
				rewind(this->stream);
			}
		}

		bool FileHttpBody::HasSize()
		{
			return this->hasSize;
		}

		bool FileHttpBody::IsChunked()
		{
			return this->chunked;
		}

		long FileHttpBody::Size()
		{
			return this->size;
		}

		size_t FileHttpBody::ReadCallback(void *ptr, size_t size, size_t nmemb)
		{
			size_t sizeRead = 0;

			while (true)
			{
				if (feof(this->stream))
					break;

				sizeRead = fread(ptr, size, nmemb, this->stream);

				if (sizeRead > 0 || this->hasRead)
					break;
			}

			this->hasRead = true;

			return sizeRead;
		}




		/********************************************************************************************
		*
		*	URLEncodedHttpBody
		*
		********************************************************************************************/


		URLEncodedHttpBody::URLEncodedHttpBody()
		{
			this->data = NULL;
			this->size = 0;
			this->readPtr = 0;
		}
		URLEncodedHttpBody::~URLEncodedHttpBody()
		{
		}


		void URLEncodedHttpBody::Add(c_string_ref key, c_string_ref value)
		{
			this->params.Add(key, value);
		}
		void URLEncodedHttpBody::Add(c_char_ptr key, c_string_ref value)
		{
			this->params.Add(key, value);
		}
		void URLEncodedHttpBody::Add(c_char_ptr key, c_char_ptr value)
		{
			this->params.Add(key, value);
		}

		void URLEncodedHttpBody::Prepare(CurlCTX *ctx)
		{
			if (this->data != NULL)
			{
				this->size = 0;
				this->readPtr = 0;
				this->tmpData = string();
			}

			this->data = NULL;

			this->params.SetCTX(ctx);

			this->tmpData = this->params.toStr();

			if (this->tmpData.size() > 0)
			{
				this->data = (char*)this->tmpData.c_str();

				if (this->data != NULL)
				{
					this->size = this->tmpData.size();

					if (ctx != NULL)
						ctx->headers = curl_slist_append(ctx->headers, "Content-Type: application/x-www-form-urlencoded");
				}
			}

		}

		bool URLEncodedHttpBody::IsChunked()
		{
			return false;
		}

		bool URLEncodedHttpBody::HasSize()
		{
			return true;
		}

		long URLEncodedHttpBody::Size()
		{
			return this->size;
		}


		size_t URLEncodedHttpBody::ReadCallback(void *ptr, size_t size, size_t nmemb)
		{
			if (this->data == NULL)
				return 0;

			size_t sizeRead = min((size_t)(this->size - this->readPtr), (size_t)(size * nmemb));
			//size_t sizeRead = min((size_t)(min(this->size - this->readPtr, 10)), (size_t)(this->size * nmemb) );

			if (sizeRead > 0)
			{
				memcpy(ptr, this->data + this->readPtr, sizeRead);
				this->readPtr += sizeRead;
			}

			return sizeRead;
		}


		/********************************************************************************************
		*
		*	Http
		*
		********************************************************************************************/

		string Http::USER_AGENT = "OAuth2CPP/1.0";
		bool Http::debug = false;


		static HttpResult* getHttpResult()
		{
			HttpResult *result = new HttpResult();

			if (result != NULL)
				memset(result, 0, sizeof(HttpResult));

			return result;
		}
		static CurlCTX* getContext()
		{
			CurlCTX *ctx = NULL;
			CURL *tmpcurl = curl_easy_init();

			if (!tmpcurl)
				throw OAUTH2CPP_EXCEPTION_HTTP;

			ctx = new CurlCTX();

			if (ctx == NULL)
				throw OAUTH2CPP_EXCEPTION_HTTP;

			memset(ctx, 0, sizeof(CurlCTX));

			ctx->curl = tmpcurl;

			return ctx;
		}
		static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
		{
			size_t realsize = size * nmemb;
			CurlCTX *ctx = (CurlCTX *)userp;

			if (ctx->memory == NULL)
				ctx->memory = (char *)malloc(ctx->size + realsize + 1);
			else
				ctx->memory = (char *)realloc(ctx->memory, ctx->size + realsize + 1);

			if (ctx->memory == NULL)
				throw OAUTH2CPP_EXCEPTION_HTTP;

			memcpy(&(ctx->memory[ctx->size]), contents, realsize);
			ctx->size += realsize;
			ctx->memory[ctx->size] = 0;

			return realsize;
		}
		static size_t ReadCallback(void *ptr, size_t size, size_t nmemb, void *userp)
		{
			HttpBody *body = (HttpBody*)userp;

			return body->ReadCallback(ptr, size, nmemb);
		}





		//HttpResult* Http::Get(HttpURL* url)
		//{
		//	return this->Request(url, NULL, HttpMethod::M_GET, NULL);
		//}
		//HttpResult* Http::Put(HttpURL* url, HttpBody* body)
		//{
		//	return this->Request(url, NULL, HttpMethod::M_PUT, body);
		//}
		//HttpResult* Http::Post(HttpURL* url, HttpBody* body)
		//{
		//	return this->Request(url, NULL, HttpMethod::M_POST, body);
		//}
		//HttpResult* Http::Delete(HttpURL* url, HttpBody* body)
		//{
		//	return this->Request(url, NULL, HttpMethod::M_DELETE, body);
		//}

		HttpResult* Http::Request(HttpURL* url, HttpMethod method, HttpBody *body, vector<string> *headers)
		{
			return this->Request(url, NULL, method, body, headers);
		}

		HttpResult* Http::Request(c_string*  url, HttpMethod method, HttpBody *body, vector<string> *headers)
		{
			return this->Request(NULL, url, method, body, headers);
		}



		HttpResult* Http::Request(HttpURL* url, c_string* urlStr, HttpMethod method, HttpBody* body, vector<string> *headers)
		{
			CurlCTX *ctx = getContext();
			HttpResult* result = getHttpResult();
			string contentLength;


			if (ctx == NULL || result == NULL || (url == NULL && urlStr == NULL))
			{
				if (result != NULL)
					this->ReleaseHttpResult(result);

				throw OAUTH2CPP_EXCEPTION_HTTP;
			}

			result->ctx = ctx;

			/* send all data to this function  */
			curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

			/* we pass our 'chunk' struct to the callback function */
			curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, (void *)ctx);

			//curl_easy_setopt(ctx->curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(ctx->curl, CURLOPT_USERAGENT, Http::USER_AGENT.c_str());

			//ctx->headers = curl_slist_append(ctx->headers, "Expect:"); 


			if (body != NULL)
			{
				body->Prepare(ctx);

				curl_easy_setopt(ctx->curl, CURLOPT_READFUNCTION, ReadCallback);
				curl_easy_setopt(ctx->curl, CURLOPT_READDATA, body);

				if (body->IsChunked())
					ctx->headers = curl_slist_append(ctx->headers, "Transfer-Encoding: chunked");
				else
					ctx->headers = curl_slist_append(ctx->headers, "Transfer-Encoding:");

				if (body->HasSize())
				{
					if (method != HttpMethod::M_PUT || body->Size() == 0)
					{
						stringstream ss;
						ss << "Content-Length: " << body->Size();
						contentLength = ss.str();
						ctx->headers = curl_slist_append(ctx->headers, contentLength.c_str());
					}

					curl_easy_setopt(ctx->curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)body->Size());
				}
			}

			if (headers != NULL && headers->size() > 0)
			{
				for (vector<string>::iterator it = headers->begin(); it != headers->end(); it++)
				{
					if (it->size() > 0)
						ctx->headers = curl_slist_append(ctx->headers, it->c_str());
				}
			}

			switch (method)
			{
			case HttpMethod::M_POST:
				curl_easy_setopt(ctx->curl, CURLOPT_POST, 1L);
				break;

			case HttpMethod::M_PUT:
				curl_easy_setopt(ctx->curl, CURLOPT_PUT, 1L);
				break;

			case HttpMethod::M_DELETE:
				curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
				break;

			default:
				break;
			}

			if (url != NULL)
			{
				url->SetCTX(ctx);

				result->url = url->toStr();

				url->SetCTX(NULL);
			}
			else if (urlStr != NULL)
			{
				result->url = *urlStr;
			}

			// set url
			curl_easy_setopt(ctx->curl, CURLOPT_URL, result->url.c_str());

			// set headers
			if (ctx->headers != NULL)
				curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, ctx->headers);

			if (Http::debug)
				curl_easy_setopt(ctx->curl, CURLOPT_VERBOSE, 1L);

			/* Perform the request, res will get the return code */
			result->curlStatus = curl_easy_perform(ctx->curl);

			curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &result->statusCode);

			/* Check for errors */
			if (result->curlStatus != CURLE_OK)
			{
				result->curlErrorMsg = (char *)curl_easy_strerror(result->curlStatus);

				if (Http::debug)
					cerr << "Curl error message: " << result->curlErrorMsg << endl;
			}
			if (Http::debug && result->ctx->memory != NULL)
				cout << "-- Start Output --" << endl << result->ctx->memory << endl << "--End Output--" << endl;

			return result;
		}



		// statics

		void Http::Init(void)
		{
			curl_global_init(CURL_GLOBAL_ALL);
		}
		void Http::Terminate(void)
		{
			curl_global_cleanup();
		}
		void Http::SetDebug(bool debug)
		{
			Http::debug = debug;
		}
		Http* Http::GetInstance(void)
		{
			static Http instance;
			return &instance;
		}

		void Http::ReleaseHttpResult(HttpResult* result)
		{
			if (result != NULL)
			{
				if (result->ctx != NULL)
				{
					if (result->ctx->headers != NULL)
						curl_slist_free_all(result->ctx->headers);

					curl_easy_cleanup(result->ctx->curl);

					if (result->ctx->memory != NULL)
						free(result->ctx->memory);

					delete result->ctx;
				}

				delete result;
			}
		}


		void Http::SetUserAgent(string userAgent)
		{
			Http::USER_AGENT = userAgent;
		}



		/********************************************************************************************
		*
		*
		*
		********************************************************************************************/

	}
}