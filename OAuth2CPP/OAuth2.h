
#ifndef _OAUTH2_API_H_
#define _OAUTH2_API_H_


#include "Http.h"
#include "Utils.h"
#include <vector>
#include <string>
#include <rapidjson/document.h>

using namespace std;



#define OA2CPP_C_AUTHORIZATION_CODE	"authorization_code"
#define OA2CPP_C_CLIENT_ID			"client_id"
#define OA2CPP_C_CLIENT_SECRET		"client_secret"
#define OA2CPP_C_REDIRECT_URI		"redirect_uri"
#define OA2CPP_C_SCOPE				"scope"
#define OA2CPP_C_STATE				"state"
#define OA2CPP_C_GRANT_TYPE			"grant_type"
#define OA2CPP_C_CODE				"code"



namespace OAuth2CPP {

	namespace CodeGrant { class AccessTokenRequest; }


	typedef struct OAUTH2CPP_API APITokens
	{
		string refresh_token;
		string access_token;
		string type;
		long expires;
	} APITokens;




	class OAUTH2CPP_API OAuth2Factory {
		friend class AuthorizationBuilder;
		friend class CodeGrant::AccessTokenRequest;

	private:
		const string authrorizeEP;
		const string accessEP;

		const string clientId;
		const string clientSecret;

	public:
		OAuth2Factory(const string &authrorizeEP, const string &accessEP, const string &clientId, const string &clientSecret = "");
		~OAuth2Factory() {};

		AuthorizationBuilder* GetAuthorizationBuilder();

	};



	class OAUTH2CPP_API AuthorizationBuilder {
		friend class OAuth2Factory;

	private:
		HttpURL url;

	private:
		AuthorizationBuilder(const OAuth2Factory &factory);

	public:
		~AuthorizationBuilder() {};

		void SetRedirectURI(const string &uri);
		void SetScope(const string &scope);
		void SetState(const string &state);

		void AddGenericVar(const string &key, const string &value);

		string GetUrl(void);
	};



	namespace CodeGrant {

		class OAUTH2CPP_API AccessTokenRequest {
			friend class OAuth2Factory;

		private:
			const string *clientId = NULL;
			const string *clientSecret = NULL;
			const string *basicAuth = NULL;

			vector<string> *headers = NULL;
			HttpParameters params;

		private:
			AccessTokenRequest(const OAuth2Factory &factory, const string &code, bool sendClientId = true, bool sendClientSecret = true, bool isBasicAuth = false);

		public:
			~AccessTokenRequest();

			void SetRedirectURI(const string &uri);

			void AddGenericVar(const string &key, const string &value);
			void AddGenericHeader(const string &header);

		};
	}

}


#endif /* _OAUTH2_API_H_ */

