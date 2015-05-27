
#include <cstdio>
#include "OAuth2.h"

using namespace OAuth2CPP;


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
	"123456789");

	Http::USER_AGENT = "Http::USER_AGENT";

	AuthorizationBuilder *builder = factory.GetAuthorizationBuilder();

	builder->SetRedirectURI("oob");

	string a = builder->GetUrl();



	delete builder;

	return 0;
}
