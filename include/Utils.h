#ifndef _UTILS_H_
#define _UTILS_H_



//#ifdef __unix__
//
//#define OS_UNIX
//
//#elif defined(_WIN32) || defined(WIN32) 
//
//#define OS_WINDOWS
//
//#include <Windows.h>
//
//#endif
//
//#include <string>

#define CURL_STATICLIB


#ifdef OAUTH2CPP_EXPORT
#   define OAUTH2CPP_API   __declspec(dllexport)
#	define EXPIMP_TEMPLATE
#else
#   define OAUTH2CPP_API   __declspec(dllimport)
#	define EXPIMP_TEMPLATE extern
#endif 

#include <string>
EXPIMP_TEMPLATE template class OAUTH2CPP_API std::basic_string< char, std::char_traits<char>, std::allocator<char> >;


#define OAUTH2CPP_OK 0
#define OAUTH2CPP_ERROR_HTTP 1
#define OAUTH2CPP_EXCEPTION_HTTP 2


#define BUFFERSIZE 65536


#endif /* _UTILS_H_ */
