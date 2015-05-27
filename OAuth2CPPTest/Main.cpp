
#include <cstdio>
#include "OAuth2.h"

using namespace OAuth2CPP;
using namespace OAuth2CPP::CodeGrant;


int main(void)
{

	string url = "http://", urlk = "abc", urlv = "123";

	HttpURL http(url);

	http.Add(urlk, urlv);
	http.Add("assdsd", urlv);
	http.Add("c", "d");
	
	string aaa = http.toStr();


	

	


	OAuth2Factory factory(
	"https://meocloud.pt/oauth2/authorize",
	"https://meocloud.pt/oauth2/token",
	"123456789", "aaaaa");

	Http::USER_AGENT = "Oauth2-dev/0.1";

	AuthorizationBuilder *builder = factory.GetAuthorizationBuilder();

	builder->SetRedirectURI("oob");

	string a = builder->GetUrl();

	
	AccessTokenRequest *tokenRequest = factory.GetCodeGrantAuthorizationRequestWithAuth("sasdasd", true);

	tokenRequest->Execute();


	delete builder;
	delete tokenRequest;

	return 0;
}
