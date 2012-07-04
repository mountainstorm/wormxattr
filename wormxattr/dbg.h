//
//  dbg.h
//  wormxattr
//
//  Created by R J Cooper on 04/09/2011.
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

#ifndef wormxattr_dbg_h
#define wormxattr_dbg_h


/*
 * Definitions
 */

#ifdef DEBUG
#define dbg_report(type, str, ...)				printf("%s: " type str, __func__, ##__VA_ARGS__)
#else
#define dbg_report(type, str, ...)				
#endif


#define dbg_info(str, ...)						dbg_report("Info: ", str, ##__VA_ARGS__)
#define dbg_warning(str, ...)					dbg_report("Warning: ", str, ##__VA_ARGS__)
#define dbg_error(str, ...)						dbg_report("Error: ", str, ##__VA_ARGS__)
#define dbg_invalidParameter(str, ...)			dbg_report("Invalid parameter: ", str, ##__VA_ARGS__)


#endif
