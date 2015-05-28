
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
using namespace rapidjson;

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
		sout << "Authorization: Basic ";

		encoder.encode(sin, sout);

		return sout.str();
	}


	CodeGrant::AccessTokenRequest* OAuth2Factory::CodeGrant_GetAuthorizationRequest(CodeGrant::AuthenticationType type, c_string_ref code)
	{
		CodeGrant::AccessTokenRequest* tokenRequest = new CodeGrant::AccessTokenRequest(*this, type, code);

		return tokenRequest;
	}


	/********************************************************************************************
	*
	*	AuthorizationBuilder
	*
	********************************************************************************************/

	AuthorizationBuilder::AuthorizationBuilder(const OAuth2Factory &factory)
	{
		this->url.SetUrl(factory.authrorizeEP);
		this->url.Add(OA2CPP_C_AUTHORIZATION_CODE, OA2CPP_C_CODE);
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

	int BaseAccessTokenRequest::Ececute(void)
	{
		int outCode = -1;
		Http *httpClient = Http::GetInstance();
		HttpResult* result = httpClient->Request(&factory->accessEP, HttpMethod::M_POST, this->body == NULL ? new EmptyHttpBody() : this->body, this->headers);
		

		if (result != NULL && result->IsCurlResponseOK())
		{
			outCode = result->statusCode;

			Document doc;
			doc.Parse(result->ctx->memory);

			if (doc.IsObject())
			{
				if (result->statusCode == 200)
				{
				}
			}
		}

		httpClient->releaseResult(result);

		return outCode;
	}



	/********************************************************************************************
	*
	*	CodeGrant::AccessTokenRequest
	*
	********************************************************************************************/

	namespace CodeGrant {

		AccessTokenRequest::AccessTokenRequest(const OAuth2Factory &factory, AuthenticationType authType, c_string_ref code)
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

			this->urlEncBody->AddParam(OA2CPP_C_GRANT_TYPE, OA2CPP_C_AUTHORIZATION_CODE);
			this->urlEncBody->AddParam(OA2CPP_C_CODE, code);

			switch (authType)
			{
			case AuthenticationType::CLIENT_ID_AND_SECRET_BASIC_AUTH:
				this->AddHeader(factory.basicAuth);
				break;

			case AuthenticationType::CLIENT_ID_AND_SECRET:
				this->urlEncBody->AddParam(OA2CPP_C_CLIENT_SECRET, factory.clientSecret);
				
				// fall-through
			case AuthenticationType::CLIENT_ID:
				this->urlEncBody->AddParam(OA2CPP_C_CLIENT_ID, factory.clientId);
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

		void AccessTokenRequest::SetRedirectURI(c_string_ref uri)
		{
			this->urlEncBody->AddParam(OA2CPP_C_REDIRECT_URI, uri);
		}


		void AccessTokenRequest::AddVar(c_string_ref key, c_string_ref value)
		{
			this->urlEncBody->AddParam(key, value);
		}

		void AccessTokenRequest::AddVar(c_char_ptr key, c_string_ref value)
		{
			this->urlEncBody->AddParam(key, value);
		}

		void AccessTokenRequest::AddVar(c_char_ptr key, c_char_ptr value)
		{
			this->urlEncBody->AddParam(key, value);
		}


		//void AccessTokenRequest::Execute(void)
		//{
		//	//string params = this->urlEncBody.toStr();
		//}
	}

}
