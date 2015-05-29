
#include <cstdio>
#include "OAuth2.h"
#include "b64\encode.h"
#include "b64\decode.h"
#include <sstream>
#include <rapidjson\rapidjson.h>
#include <rapidjson\document.h>

using namespace OAuth2CPP;
using namespace OAuth2CPP::Core;
using namespace OAuth2CPP::CodeGrant;
using namespace OAuth2CPP::Request;
using namespace base64;
using namespace rapidjson;

int main(void)
{

	Http::USER_AGENT = "Oauth2-dev/0.1";
	Http::SetDebug(true);

	Http::Init();

	OAuth2Factory factory(
			"https://meocloud.pt/oauth2/authorize",
			"https://meocloud.pt/oauth2/token",
			"abc",
			"def");

	AuthorizationBuilder *builder = factory.GetAuthorizationBuilder();
	//builder->SetRedirectURI("oob");

	string url = builder->GetUrl();

	cout << url << endl;

	AuthorizationBuilder::ReleaseAuthorizationBuilder(builder);

	APITokens tokens;
	rapidjson::Document *json = NULL;

	string authcode = "345";
	
	//AccessTokenRequest *tokenRequest = factory.CodeGrant_GetAuthorizationRequest(authcode, AuthenticationType::CLIENT_ID_AND_SECRET_BASIC_AUTH);

	//tokenRequest->SetRedirectURI("oob");

	//AuthorizationResponse response = tokenRequest->Execute(tokens, &json);

	//cout << OA2CPP_C_ACCESS_TOKEN << ":" << tokens.access_token << endl;
	//cout << OA2CPP_C_REFRESH_TOKEN << ":" << tokens.refresh_token << endl;
	//cout << OA2CPP_C_TOKEN_TYPE << ":" << tokens.token_type << endl;
	//cout << OA2CPP_C_EXPIRES_IN << ":" << tokens.expires_in << endl;

	APITokens tokenss;

	HttpRequest *request = factory.GetHttpRequest(tokenss);

	HttpResult *result = request->Request("https://publicapi.meocloud.pt/1/Account/Info");

	HttpRequest::ReleaseHttpResult(result);
	HttpRequest::ReleaseHttpRequest(request);


	OAuth2Factory::ReleaseDocument(json);
	//AccessTokenRequest::ReleaseAccessTokenRequest(tokenRequest);
	

	Http::Terminate();


	return 0;
}
