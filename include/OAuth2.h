
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
#define OA2CPP_C_REFRESH_TOKEN		"refresh_token"
#define OA2CPP_C_ACCESS_TOKEN		"access_token"
#define OA2CPP_C_TOKEN_TYPE			"token_type"
#define OA2CPP_C_EXPIRES_IN			"expires_in"
#define OA2CPP_C_RESPONSE_TYPE		"response_type"



namespace OAuth2CPP {

	namespace CodeGrant {
		class AccessTokenRequest;

		typedef enum OAUTH2CPP_API AuthenticationType AuthenticationType;
		//typedef enum OAUTH2CPP_API {
		//	NONE = 0,
		//	CLIENT_ID,
		//	CLIENT_ID_AND_SECRET,
		//	CLIENT_ID_AND_SECRET_BASIC_AUTH
		//} AuthenticationType;
	};

	class AuthorizationBuilder;


	typedef struct OAUTH2CPP_API APITokens
	{
		string refresh_token;
		string access_token;
		string token_type;
		long expires_in = -1;
	} APITokens;




	class OAUTH2CPP_API OAuth2Factory {

	public:
		const string authrorizeEP;
		const string accessEP;

		const string clientId;
		const string clientSecret;
		const string basicAuth;
		


	public:
		OAuth2Factory(c_string_ref authrorizeEP, c_string_ref accessEP, c_string_ref clientId, c_string_ref clientSecret = "");
		~OAuth2Factory() {};

	private:
		string computeBasicAuth(void);

	public:

		AuthorizationBuilder* GetAuthorizationBuilder();
		CodeGrant::AccessTokenRequest* CodeGrant_GetAuthorizationRequest(CodeGrant::AuthenticationType type, c_string_ref code);

		static void ReleaseDocument(rapidjson::Document *doc);
	};



	class OAUTH2CPP_API AuthorizationBuilder {
		friend class OAuth2Factory;

	private:
		HttpURL url;

	private:
		AuthorizationBuilder(const OAuth2Factory &factory);

	public:
		~AuthorizationBuilder() {};

		void SetRedirectURI(c_string_ref uri);
		void SetScope(c_string_ref scope);
		void SetState(c_string_ref state);

		void AddGenericVar(c_string_ref key, c_string_ref value);

		string GetUrl(void);

		static void ReleaseAuthorizationBuilder(AuthorizationBuilder *builder);
	};


	typedef OAUTH2CPP_API enum {
		OK = 0,
		E_INTERNAL,
		E_MALFORMED_RESPONSE,
		E_INVALID_REQUEST,
		E_INVALID_CLIENT,
		E_INVALID_GRANT,
		E_UNAUTHORIZED_CLIENT,
		E_UNSUPPORTED_GRANT_TYPE,
		E_INVALID_SCOPE,
		E_OTHER
	} AuthorizationResponse;

	class OAUTH2CPP_API BaseAccessTokenRequest {
	
	protected:
		const OAuth2Factory *factory = NULL;
		HttpBody *body = NULL;
		HttpURL *url = NULL;
		vector<string> *headers = NULL;

		BaseAccessTokenRequest(const OAuth2Factory &factory);
		~BaseAccessTokenRequest();

	public:

		virtual void AddVar(c_string_ref key, c_string_ref value) = 0;
		virtual void AddVar(c_char_ptr key, c_string_ref value) = 0;
		virtual void AddVar(c_char_ptr key, c_char_ptr value) = 0;

		virtual void AddHeader(c_string_ref header);

		AuthorizationResponse Execute(APITokens &tokens, rapidjson::Document **docOut = NULL);
	};



	namespace CodeGrant {

		enum AuthenticationType {
			NONE = 0,
			CLIENT_ID,
			CLIENT_ID_AND_SECRET,
			CLIENT_ID_AND_SECRET_BASIC_AUTH
		};

		class OAUTH2CPP_API AccessTokenRequest final : public BaseAccessTokenRequest {
			friend class OAuth2Factory;

		private:
			URLEncodedHttpBody *urlEncBody = NULL;
			//HttpURL *urlEncBody = NULL;

		private:
			AccessTokenRequest(const OAuth2Factory &factory, AuthenticationType authType, c_string_ref code, bool isRefreshToken = false);

		public:
			~AccessTokenRequest();

			void SetRedirectURI(c_string_ref uri);
			void SetScope(c_string_ref scope);

			void AddVar(c_string_ref key, c_string_ref value);
			void AddVar(c_char_ptr key, c_string_ref value);
			void AddVar(c_char_ptr key, c_char_ptr value);

			static void ReleaseAccessTokenRequest(AccessTokenRequest* request);

		};
	}

}


#endif /* _OAUTH2_API_H_ */

