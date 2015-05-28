
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

	char * str = "{\"error\": \"unsupported_grant_type\"}";
	Document doc;
	doc.Parse(str);
	if (doc.IsObject())
	{
		cout << "aa";

	}

	OAuth2Factory factory(
			"https://meocloud.pt/oauth2/authorize",
			"https://meocloud.pt/oauth2/token",
			"123456789", "aaaaa");

	AuthorizationBuilder *builder = factory.GetAuthorizationBuilder();
	builder->SetRedirectURI("oob");

	string a = builder->GetUrl();

	
	AccessTokenRequest *tokenRequest = factory.CodeGrant_GetAuthorizationRequest(AuthenticationType::CLIENT_ID_AND_SECRET, "sasdasd");

	int code = tokenRequest->Ececute();



	delete builder;
	delete tokenRequest;

	Http::Terminate();


	return 0;
}
