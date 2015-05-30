
#include <cstdio>
#include "OAuth2.h"
#include "b64\encode.h"
#include "b64\decode.h"
#include <iostream>
#include <sstream> 
#include <rapidjson/document.h>
#include <rapidjson/filewritestream.h>
#include <rapidjson/filereadstream.h>
#include <rapidjson/prettywriter.h>

#ifdef OS_UNIX
#include <sys/stat.h>
#endif

using namespace std;
using namespace OAuth2CPP::Core;

namespace OAuth2CPP {


	/********************************************************************************************
	*
	*	OAuth2Factory
	*
	********************************************************************************************/

	static string computeBasicAuth()
	{

	}

	OAuth2Factory::OAuth2Factory(c_string_ref authrorizeEP, c_string_ref accessEP, c_string_ref clientId, c_string_ref clientSecret)
		: authrorizeEP(authrorizeEP), accessEP(accessEP), clientId(clientId), clientSecret(clientSecret), basicAuth(this->computeBasicAuth())
	{
	}

	AuthorizationBuilder* OAuth2Factory::GetAuthorizationBuilder()
	{
		AuthorizationBuilder *builder = new AuthorizationBuilder(*this);

		return builder;
	}

	string OAuth2Factory::computeBasicAuth(void)
	{
		stringstream sin, sout;
		base64::encoder encoder;

		sin << this->clientId << ":" << this->clientSecret;
		sout << OA2CPP_C_AUTH_BASIC;

		encoder.encode(sin, sout);

		return sout.str();
	}


	CodeGrant::AccessTokenRequest* OAuth2Factory::CodeGrant_GetAuthorizationRequest(c_string_ref code, CodeGrant::AuthenticationType type)
	{
		return new CodeGrant::AccessTokenRequest(*this, code, type);
	}


	Request::HttpRequest* OAuth2Factory::GetHttpRequest(APITokens &tokens, Request::AuthenticationType type)
	{
		return new Request::HttpRequest(*this, tokens, type);
	}


	// static

	void OAuth2Factory::ReleaseDocument(rapidjson::Document *doc)
	{
		if (doc != NULL)
			delete doc;
	}


	/********************************************************************************************
	*
	*	AuthorizationBuilder
	*
	********************************************************************************************/

	AuthorizationBuilder::AuthorizationBuilder(const OAuth2Factory &factory)
	{
		this->url.SetUrl(factory.authrorizeEP);
		this->url.Add(OA2CPP_C_RESPONSE_TYPE, OA2CPP_C_CODE);
		this->url.Add(OA2CPP_C_CLIENT_ID, factory.clientId);
	}

	void AuthorizationBuilder::AddGenericVar(c_string_ref key, c_string_ref value)
	{
		this->url.Add(key, value);
	}


	void AuthorizationBuilder::SetRedirectURI(c_string_ref uri)
	{
		this->url.Add(OA2CPP_C_REDIRECT_URI, uri);
	}
	void AuthorizationBuilder::SetScope(c_string_ref scope)
	{
		this->url.Add(OA2CPP_C_SCOPE, scope);
	}
	void AuthorizationBuilder::SetState(c_string_ref state)
	{
		this->url.Add(OA2CPP_C_STATE, state);
	}

	string AuthorizationBuilder::GetUrl(void)
	{
		return this->url.toStr();
	}


	void AuthorizationBuilder::ReleaseAuthorizationBuilder(AuthorizationBuilder *builder)
	{
		if (builder != NULL)
			delete builder;
	}




	/********************************************************************************************
	*
	*	BaseAccessTokenRequest
	*
	********************************************************************************************/

	BaseAccessTokenRequest::BaseAccessTokenRequest(const OAuth2Factory &factory)
	{
		this->factory = &factory;
	}

	BaseAccessTokenRequest::~BaseAccessTokenRequest()
	{
		if (this->headers != NULL)
			delete this->headers;
	}

	void BaseAccessTokenRequest::AddHeader(c_string_ref header)
	{
		if (this->headers == NULL)
			this->headers = new vector<string>();

		this->headers->push_back(header);
	}

	AuthorizationResponse BaseAccessTokenRequest::Execute(APITokens &tokens, rapidjson::Document **docOut)
	{
		Http *httpClient = Http::GetInstance();
		HttpResult* result = httpClient->Request(&factory->accessEP, HttpMethod::M_POST, this->body == NULL ? new EmptyHttpBody() : this->body, this->headers);
		AuthorizationResponse response = AuthorizationResponse::E_INTERNAL;

		if (result != NULL && result->IsCurlResponseOK())
		{
			rapidjson::Document *doc = new rapidjson::Document;
			doc->Parse(result->ctx->memory);

			if (doc->IsObject())
			{
				if (result->statusCode != 200)
				{
					if (doc->HasMember("error") && (*doc)["error"].IsString())
					{
						string error = (*doc)["error"].GetString();

						if (!error.compare("invalid_request"))
							response = AuthorizationResponse::E_INVALID_REQUEST;

						else if (!error.compare("invalid_client"))
							response = AuthorizationResponse::E_INVALID_CLIENT;

						else if (!error.compare("invalid_grant"))
							response = AuthorizationResponse::E_INVALID_GRANT;

						else if (!error.compare("unauthorized_client"))
							response = AuthorizationResponse::E_UNAUTHORIZED_CLIENT;

						else if (!error.compare("unsupported_grant_type"))
							response = AuthorizationResponse::E_UNSUPPORTED_GRANT_TYPE;

						else if (!error.compare("invalid_scope"))
							response = AuthorizationResponse::E_INVALID_SCOPE;
					}
				}
				else
				{
					if (doc->HasMember(OA2CPP_C_ACCESS_TOKEN) && (*doc)[OA2CPP_C_ACCESS_TOKEN].IsString()
						&& doc->HasMember(OA2CPP_C_REFRESH_TOKEN) && (*doc)[OA2CPP_C_REFRESH_TOKEN].IsString())
					{
						tokens.access_token = (*doc)[OA2CPP_C_ACCESS_TOKEN].GetString();
						tokens.refresh_token = (*doc)[OA2CPP_C_REFRESH_TOKEN].GetString();

						response = (!tokens.refresh_token.empty() && !tokens.access_token.empty())
										? AuthorizationResponse::OK
										: AuthorizationResponse::E_MALFORMED_RESPONSE;

						if (doc->HasMember(OA2CPP_C_TOKEN_TYPE) && (*doc)[OA2CPP_C_TOKEN_TYPE].IsString())
							tokens.token_type = (*doc)[OA2CPP_C_TOKEN_TYPE].GetString();

						if (doc->HasMember(OA2CPP_C_EXPIRES_IN) && (*doc)[OA2CPP_C_EXPIRES_IN].IsInt64())
							tokens.expires_in = (*doc)[OA2CPP_C_EXPIRES_IN].GetInt64();
					}
				}

				if (docOut != NULL)
				{
					*docOut = doc;
					doc = NULL;
				}
			}

			if (doc != NULL)
				delete doc;
		}

		httpClient->ReleaseHttpResult(result);

		return response;
	}



	/********************************************************************************************
	*
	*	CodeGrant::AccessTokenRequest
	*
	********************************************************************************************/

	namespace CodeGrant {

		AccessTokenRequest::AccessTokenRequest(const OAuth2Factory &factory, c_string_ref code, AuthenticationType authType, bool isRefreshToken)
			: BaseAccessTokenRequest(factory)
		{
			// validate
			switch (authType)
			{
			case AuthenticationType::CLIENT_ID_AND_SECRET_BASIC_AUTH:
				if (factory.basicAuth.size() == 0)
					authType = AuthenticationType::CLIENT_ID_AND_SECRET;

				// fall-through
			case AuthenticationType::CLIENT_ID_AND_SECRET:
				if (factory.clientSecret.size() == 0)
					authType = AuthenticationType::CLIENT_ID;

				// fall-through
			case AuthenticationType::CLIENT_ID:
				if (factory.clientId.size() == 0)
					authType = AuthenticationType::NONE;
			}

			this->urlEncBody = new URLEncodedHttpBody();
			this->body = this->urlEncBody;

			if (isRefreshToken)
			{
				this->urlEncBody->Add(OA2CPP_C_GRANT_TYPE, OA2CPP_C_REFRESH_TOKEN);
				this->urlEncBody->Add(OA2CPP_C_REFRESH_TOKEN, code);
			}
			else
			{
				this->urlEncBody->Add(OA2CPP_C_GRANT_TYPE, OA2CPP_C_AUTHORIZATION_CODE);
				this->urlEncBody->Add(OA2CPP_C_CODE, code);
			}

			switch (authType)
			{
			case AuthenticationType::CLIENT_ID_AND_SECRET_BASIC_AUTH:
				this->AddHeader(factory.basicAuth);
				break;

			case AuthenticationType::CLIENT_ID_AND_SECRET:
				this->urlEncBody->Add(OA2CPP_C_CLIENT_SECRET, factory.clientSecret);
				
				// fall-through
			case AuthenticationType::CLIENT_ID:
				this->urlEncBody->Add(OA2CPP_C_CLIENT_ID, factory.clientId);
				break;
			}
		}
	
		AccessTokenRequest::~AccessTokenRequest()
		{
			if (this->urlEncBody != NULL)
			{
				delete this->urlEncBody;
				this->urlEncBody = NULL;
				this->body = NULL;
			}
		}

		void AccessTokenRequest::SetScope(c_string_ref scope)
		{
			this->urlEncBody->Add(OA2CPP_C_SCOPE, scope);
		}

		void AccessTokenRequest::SetRedirectURI(c_string_ref uri)
		{
			this->urlEncBody->Add(OA2CPP_C_REDIRECT_URI, uri);
		}


		void AccessTokenRequest::AddVar(c_string_ref key, c_string_ref value)
		{
			this->urlEncBody->Add(key, value);
		}

		void AccessTokenRequest::AddVar(c_char_ptr key, c_string_ref value)
		{
			this->urlEncBody->Add(key, value);
		}

		void AccessTokenRequest::AddVar(c_char_ptr key, c_char_ptr value)
		{
			this->urlEncBody->Add(key, value);
		}



		void AccessTokenRequest::ReleaseAccessTokenRequest(AccessTokenRequest* request)
		{
			if (request != NULL)
				delete request;
		}

	}



	/********************************************************************************************
	*
	*	HttpRequest::HttpRequest
	*
	********************************************************************************************/

	namespace Request {

		HttpRequest::HttpRequest(const OAuth2Factory &factory, APITokens &tokens, AuthenticationType type)
		{
			this->tokens = &tokens;
			this->authType = type;

			if (this->authType == AuthenticationType::HEADER && !tokens.token_type.compare("Bearer") || !tokens.token_type.compare("bearer"))
			{
				stringstream ss;
				ss << OA2CPP_C_AUTH_BEARER << tokens.access_token;

				this->AddHeader(ss.str());
			}
			else{
				this->authType = AuthenticationType::URI;
				this->AddHeader("Cache-Control: no-store");
			}
		}


		HttpRequest::~HttpRequest()
		{
			if (this->headers != NULL)
				delete this->headers;
		}



		void HttpRequest::AddHeader(c_string_ref header)
		{
			if (this->headers == NULL)
				this->headers = new vector<string>();

			this->headers->push_back(header);
		}


		HttpResult* HttpRequest::Request(HttpURL &url, HttpMethod method, HttpBody *body)
		{
			Http *httpClient = Http::GetInstance();

			if (this->authType == AuthenticationType::URI)
				url.Add(OA2CPP_C_ACCESS_TOKEN, this->tokens->access_token);
			
			return httpClient->Request(&url, method, body, this->headers);
		}

		HttpResult* HttpRequest::Request(c_string_ref url, HttpMethod method, HttpBody *body)
		{
			Http *httpClient = Http::GetInstance();

			HttpURL hURL;
			hURL.SetUrl(url);

			if (this->authType == AuthenticationType::URI)
				hURL.Add(OA2CPP_C_ACCESS_TOKEN, this->tokens->access_token);

			return httpClient->Request(&hURL, method, body, this->headers);
		}


		void HttpRequest::ReleaseHttpRequest(HttpRequest *request)
		{
			if (request != NULL)
				delete request;
		}
		void HttpRequest::ReleaseHttpResult(HttpResult *result)
		{
			Http::ReleaseHttpResult(result);
		}
	}




}
