//
//  audit.h
//  wormxattr
//
//  Created by R J Cooper on 19/10/2011.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//  
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//  
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//

#ifndef wormxattr_audit_h
#define wormxattr_audit_h


#include <sys/kauth.h>
#include <sys/syslog.h>


/*
 * Definitions
 */

__private_extern__ void audit_log(const char* str, ...);


/**
 * @brief	audits a request that has been denied; prints out the calling users uid/gid and the error.
 *
 * @param	cred		a kauth_cred_t - the callers credentials; this macro will evaluate cred multiple times
 * @param	str			the printf style format string for the output message
 */
#define audit_deny(cred, str, ...)			audit_log("User:Group[%d:%d]; " str, kauth_cred_getuid(cred), kauth_cred_getgid(cred), ##__VA_ARGS__)


#endif
