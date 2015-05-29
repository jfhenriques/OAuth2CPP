
#include <cstdio>
#include "OAuth2.h"
#include "b64\encode.h"
#include "b64\decode.h"
#include <sstream>
#include <rapidjson\rapidjson.h>
#include <rapidjson\document.h>

using namespace OAuth2CPP;
using namespace OAuth2CPP::CodeGrant;
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
			"aaa",
			"bbb");

	AuthorizationBuilder *builder = factory.GetAuthorizationBuilder();
	//builder->SetRedirectURI("oob");

	string url = builder->GetUrl();

	cout << url << endl;

	AuthorizationBuilder::ReleaseAuthorizationBuilder(builder);

	APITokens tokens;
	rapidjson::Document *json = NULL;

	string authcode = "abc";
	
	AccessTokenRequest *tokenRequest = factory.CodeGrant_GetAuthorizationRequest(AuthenticationType::CLIENT_ID_AND_SECRET_BASIC_AUTH, authcode);

	tokenRequest->SetRedirectURI("oob");

	AuthorizationResponse response = tokenRequest->Execute(tokens, &json);


	OAuth2Factory::ReleaseDocument(json);
	AccessTokenRequest::ReleaseAccessTokenRequest(tokenRequest);
	

	Http::Terminate();


	return 0;
}
