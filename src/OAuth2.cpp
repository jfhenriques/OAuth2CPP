
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

	OAuth2Factory::OAuth2Factory(const string &authrorizeEP, const string &accessEP, const string &clientId, const string &clientSecret)
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


	CodeGrant::AccessTokenRequest* OAuth2Factory::codeGrant_GetAuthorizationRequest(const string &code, bool sendClientId, bool sendClientSecret, bool isBasicAuth)
	{
		CodeGrant::AccessTokenRequest* tokenRequest = new CodeGrant::AccessTokenRequest(*this, code, sendClientId, sendClientSecret, isBasicAuth);

		return tokenRequest;
	}


	CodeGrant::AccessTokenRequest* OAuth2Factory::CodeGrant_GetAuthorizationRequest(const string &code)
	{
		return this->codeGrant_GetAuthorizationRequest(code, false, false, false);
	}
	CodeGrant::AccessTokenRequest* OAuth2Factory::CodeGrant_GetAuthorizationRequest_WithId(const string &code)
	{
		return this->codeGrant_GetAuthorizationRequest(code, true, false, false);
	}
	CodeGrant::AccessTokenRequest* OAuth2Factory::CodeGrant_GetAuthorizationRequest_WithAuth(const string &code, bool isBasicAuth)
	{
		return this->codeGrant_GetAuthorizationRequest(code, true, true, isBasicAuth);
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

	void AuthorizationBuilder::AddGenericVar(const string &key, const string &value)
	{
		this->url.Add(key, value);
	}


	void AuthorizationBuilder::SetRedirectURI(const string &uri)
	{
		this->url.Add(OA2CPP_C_REDIRECT_URI, uri);
	}
	void AuthorizationBuilder::SetScope(const string &scope)
	{
		this->url.Add(OA2CPP_C_SCOPE, scope);
	}
	void AuthorizationBuilder::SetState(const string &state)
	{
		this->url.Add(OA2CPP_C_STATE, state);
	}

	string AuthorizationBuilder::GetUrl(void)
	{
		return this->url.toStr();
	}




	/********************************************************************************************
	*
	*	CodeGrant::AccessTokenRequest
	*
	********************************************************************************************/

	namespace CodeGrant {

		AccessTokenRequest::AccessTokenRequest(const OAuth2Factory &factory, const string &code, bool sendClientId, bool sendClientSecret, bool isBasicAuth)
		{
			if (!sendClientId || factory.clientId.size() == 0)
				sendClientId = false;

			if (!sendClientId || !sendClientSecret || factory.clientSecret.size() == 0)
				sendClientSecret = false;

			if (!sendClientSecret || !isBasicAuth || factory.basicAuth.size() == 0)
				isBasicAuth = false;


			this->params.Add(OA2CPP_C_GRANT_TYPE, OA2CPP_C_AUTHORIZATION_CODE);
			this->params.Add(OA2CPP_C_CODE, code);

			if (isBasicAuth)
				this->AddGenericHeader(factory.basicAuth);

			else
			{
				if (sendClientId)
					this->params.Add(OA2CPP_C_CLIENT_ID, factory.clientId);

				if (sendClientSecret)
					this->params.Add(OA2CPP_C_CLIENT_SECRET, factory.clientSecret);
			}
		}

		AccessTokenRequest::~AccessTokenRequest()
		{
			if (this->headers != NULL)
				delete this->headers;
		}
	

		void AccessTokenRequest::SetRedirectURI(const string &uri)
		{
			this->params.Add(OA2CPP_C_REDIRECT_URI, uri);
		}

		void AccessTokenRequest::AddGenericVar(const string &key, const string &value)
		{
			this->params.Add(key, value);
		}
		void AccessTokenRequest::AddGenericHeader(const string &header)
		{
			if (this->headers == NULL)
				this->headers = new vector<string>();

			this->headers->push_back(header);
		}

		void AccessTokenRequest::Execute(void)
		{
			string params = this->params.toStr();
		}
	}

}
