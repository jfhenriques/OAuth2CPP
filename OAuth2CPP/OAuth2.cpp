
#include <cstdio>
#include "OAuth2.h"
#include "base64.h"
#include <iostream>
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

	OAuth2Factory::OAuth2Factory(const string &authrorizeEP, const string &accessEP, const string &clientId, const string &clientSecret)
		: authrorizeEP(authrorizeEP), accessEP(accessEP), clientId(clientId), clientSecret(clientSecret)
	{
	}

	AuthorizationBuilder* OAuth2Factory::GetAuthorizationBuilder()
	{
		AuthorizationBuilder *builder = new AuthorizationBuilder(*this);


		return builder;
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
	*	AuthorizationBuilder
	*
	********************************************************************************************/

	namespace CodeGrant {

		AccessTokenRequest::AccessTokenRequest(const OAuth2Factory &factory, const string &code, bool sendClientId, bool sendClientSecret, bool isBasicAuth)
		{
			this->clientId = sendClientId ? &factory.clientId : NULL;
			this->clientSecret = (sendClientId && sendClientSecret) ? &factory.clientSecret : NULL;

			if (isBasicAuth && this->clientId == NULL || this->clientSecret == NULL)
				this->basicAuth = NULL;

			else
			{
				string auth = *this->clientId + ":" + *this->clientSecret;

				this->basicAuth = &base64_encode(reinterpret_cast<const unsigned char*>(auth.c_str()), auth.length());
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
	}

}
