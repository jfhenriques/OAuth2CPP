
#include <cstdio>
#include "OAuth2.h"
#include "b64\encode.h"
#include "b64\decode.h"
#include <sstream>

using namespace OAuth2CPP;
using namespace OAuth2CPP::CodeGrant;
using namespace base64;

int main(void)
{

	Http::USER_AGENT = "Oauth2-dev/0.1";


	OAuth2Factory factory(
			"https://meocloud.pt/oauth2/authorize",
			"https://meocloud.pt/oauth2/token",
			"123456789", "aaaaa");

	AuthorizationBuilder *builder = factory.GetAuthorizationBuilder();
	builder->SetRedirectURI("oob");

	string a = builder->GetUrl();

	
	AccessTokenRequest *tokenRequest = factory.CodeGrant_GetAuthorizationRequest_WithAuth("sasdasd", true);

	tokenRequest->Execute();


	delete builder;
	delete tokenRequest;

	return 0;
}
