//
//  wormxattr_test.m
//  wormxattr_test
//
//  Created by R J Cooper on 20/10/2011.
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

#import "wormxattr_test.h"
#include <sys/xattr.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <dirent.h>

#define kMutableFile				"mutableFile"
#define kMutableDir					"mutableDir"
#define kWormFile					"wormFile"
#define kWormDir					"wormDir"

#define kWorm_attributeName			"com.mountainstorm.Worm"
#define kTest_attributeName			"com.mountainstorm.Test"

@implementation wormxattr_test

- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
	(void) system("touch " kMutableFile);
	(void) system("chmod +x " kMutableFile);	
	(void) system("mkdir " kMutableDir);
	(void) system("chmod +x " kMutableDir);	

	(void) system("touch " kWormFile);
	(void) system("chmod +x " kWormFile);
	(void) system("xattr -w " kWorm_attributeName " 0 " kWormFile);
	
	(void) system("mkdir " kWormDir);
	(void) system("chmod +x " kWormDir);
	(void) system("xattr -wr " kWorm_attributeName " 0 " kWormDir);
}

- (void)tearDown
{
    // Tear-down code here.
	(void) system("sudo xattr -dr " kWorm_attributeName " " kWormDir " 2>/dev/null");
	(void) system("rm -r " kWormDir " 2>/dev/null");	
	(void) system("sudo xattr -d " kWorm_attributeName " " kWormFile " 2>/dev/null");
	(void) system("rm " kWormFile " 2>/dev/null");

	(void) system("rm -r " kMutableDir " 2>/dev/null");	
	(void) system("rm " kMutableFile " 2>/dev/null");
	
    [super tearDown];
}

- (void)vnode_check_access:(char*)filename info:(NSString*)info mutable:(BOOL)mutable
{
	STAssertEquals(access(filename, R_OK), 0, [info stringByAppendingString:@"; R_OK"]);
	STAssertEquals(access(filename, X_OK), 0, [info stringByAppendingString:@"; X_OK"]);
	STAssertEquals(access(filename, F_OK), 0, [info stringByAppendingString:@"; F_OK"]);	
	if (mutable) {
		STAssertEquals(access(filename, W_OK), 0, [info stringByAppendingString:@"; W_OK"]);
		STAssertEquals(access(filename, R_OK | W_OK | X_OK), 0, [info stringByAppendingString:@"; R_OK | W_OK | X_OK"]);
	} else {
		int err = access(filename, W_OK);
		STAssertEquals(err, -1, [info stringByAppendingString:@"; W_OK"]);
		STAssertEquals(errno, EPERM, [info stringByAppendingString:@" errno; W_OK"]);		
		err = access(filename, R_OK | W_OK | X_OK);
		STAssertEquals(err, -1, [info stringByAppendingString:@"; R_OK | W_OK | X_OK"]);
		STAssertEquals(errno, EPERM, [info stringByAppendingString:@" errno; R_OK | W_OK | X_OK"]);
	}
}

- (void)test_vnode_check_access_mutable_file
{
	[self vnode_check_access:kMutableFile info:@"Mutable file" mutable:YES];
}

- (void)test_vnode_check_access_mutable_dir
{
	[self vnode_check_access:kMutableDir info:@"Mutable dir" mutable:YES];
}

- (void)test_vnode_check_access_immutable_file
{
	[self vnode_check_access:kWormFile info:@"Immutable file" mutable:NO];
}

- (void)test_vnode_check_access_immutable_dir
{
	[self vnode_check_access:kWormDir info:@"Immutable dir" mutable:YES]; // we shouldn't effect dir access calls
}


/* vnode_check_deleteextattr */
- (void)test_vnode_check_deleteextattr_mutable_file
{
	int err = removexattr(kMutableFile, kWorm_attributeName, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, ENOATTR, @"errno");
}

- (void)test_vnode_check_deleteextattr_mutable_dir
{
	int err = removexattr(kMutableDir, kWorm_attributeName, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, ENOATTR, @"errno");
}

- (void)test_vnode_check_deleteextattr_immutable_file
{
	int err = removexattr(kWormFile, kWorm_attributeName, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}

- (void)test_vnode_check_deleteextattr_immutable_dir
{
	int err = removexattr(kWormFile, kWorm_attributeName, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}


/* vnode_check_exchangedata */
- (void)test_vnode_check_exchangedata
{
	int err = exchangedata(kMutableFile, kWormFile, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");

	err = exchangedata(kWormFile, kMutableFile, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}


/* vnode_check_open */
- (void)vnode_check_open:(char*)filename info:(NSString*)info mutable:(BOOL)mutable
{
	int fd = open(filename, O_RDONLY);
	STAssertTrue(fd > 0, [info stringByAppendingString:@"; O_RDONLY"]);
	close(fd);
	
	if (mutable) {
		fd = open(filename, O_WRONLY);
		STAssertTrue(fd > 0, [info stringByAppendingString:@"; O_WRONLY"]);
		close(fd);
		
		fd = open(filename, O_RDWR);
		STAssertTrue(fd > 0, [info stringByAppendingString:@"; O_RDWR"]);
		close(fd);
		
		fd = open(filename, O_APPEND);
		STAssertTrue(fd > 0, [info stringByAppendingString:@"; O_APPEND"]);
		close(fd);

		fd = open(filename, O_TRUNC);
		STAssertTrue(fd > 0, [info stringByAppendingString:@"; O_TRUNC"]);
		close(fd);
	} else {
		fd = open(filename, O_WRONLY);
		STAssertEquals(fd, -1, [info stringByAppendingString:@"; O_WRONLY"]);
		STAssertEquals(errno, EPERM, [info stringByAppendingString:@"; O_WRONLY"]);
		
		fd = open(filename, O_RDWR);
		STAssertEquals(fd, -1, [info stringByAppendingString:@"; O_RDWR"]);
		STAssertEquals(errno, EPERM, [info stringByAppendingString:@"; O_RDWR"]);
		
		fd = open(filename, O_APPEND);
		STAssertEquals(fd, -1, [info stringByAppendingString:@"; O_APPEND"]);
		STAssertEquals(errno, EPERM, [info stringByAppendingString:@"; O_APPEND"]);
		
		fd = open(filename, O_TRUNC);
		STAssertEquals(fd, -1, [info stringByAppendingString:@"; O_TRUNC"]);
		STAssertEquals(errno, EPERM, [info stringByAppendingString:@"; O_TRUNC"]);
	}
}

- (void)test_vnode_check_open_mutable_file
{
	[self vnode_check_open:kMutableFile info:@"Mutable file" mutable:YES];
}

- (void)test_vnode_check_open_mutable_dir
{
	DIR* dp = opendir(kMutableDir);
	STAssertTrue(dp != NULL, @"retVal");
	(void) closedir(dp);
}

- (void)test_vnode_check_open_immutable_file
{
	[self vnode_check_open:kWormFile info:@"Immutable file" mutable:NO];
}

- (void)test_vnode_check_open_immutable_dir
{
	DIR* dp = opendir(kWormDir);
	STAssertTrue(dp != NULL, @"retVal");
	(void) closedir(dp);
}


/* vnode_check_rename_from */
/* vnode_notify_rename */
- (void)test_check_rename_from_mutable_vnode
{
	ssize_t err = 0;
	char state = 0;
	STAssertEquals(rename(kMutableFile, kMutableDir "/" kMutableFile), 0, @"move mutable file to mutable dir");
	err = getxattr(kMutableDir "/" kMutableFile, kWorm_attributeName, &state, sizeof(state), 0, 0);
	STAssertTrue(err == -1, @"verify mutable file move didnt add attribute; retVal");
	STAssertEquals(errno, ENOATTR, @"verify mutable file move didnt add attribute; errno");
	
	STAssertEquals(rename(kWormFile, kMutableDir "/" kWormFile), 0, @"move immutable file to mutable dir");
	STAssertEquals(rename(kMutableDir "/" kMutableFile, kMutableFile), 0, @"move mutable file out of mutable dir");
	STAssertEquals(rename(kMutableDir "/" kWormFile, kWormFile), 0, @"move immutable file out of mutable dir");
}

- (void)test_check_rename_from_immutable_vnode
{
	int err = 0;
	char state = 0;
	STAssertEquals(rename(kMutableFile, kWormDir "/" kMutableFile), 0, @"move mutable file to immutable dir");
	STAssertTrue(getxattr(kWormDir "/" kMutableFile, kWorm_attributeName, &state, sizeof(state), 0, 0) == 1, 0, @"verify mutable file move did add attribute; retVal");
	
	STAssertEquals(rename(kWormFile, kWormDir "/" kWormFile), 0, @"move immutable file to immutable dir");
	err = rename(kWormDir "/" kMutableFile, kMutableFile);
	STAssertEquals(err, -1, @"move mutable file out of immutable dir; retVal");
	STAssertEquals(errno, EPERM, @"move mutable file out of immutable dir; errno");
	err = rename(kWormDir "/" kWormFile, kWormFile);
	STAssertEquals(err, -1, @"move immutable file out of immutable dir; retVal");
	STAssertEquals(errno, EPERM, @"move immutable file out of immutable dir; errno");
}


/* vnode_check_setattrlist */
- (void)test_vnode_check_setextattr_mutable_file
{
	char state = 1;
	STAssertEquals(setxattr(kMutableFile, kTest_attributeName, &state, sizeof(state), 0, 0), 0, @"retVal");
}

- (void)test_vnode_check_setextattr_mutable_dir
{
	char state = 1;
	STAssertEquals(setxattr(kMutableDir, kTest_attributeName, &state, sizeof(state), 0, 0), 0, @"retVal");
}

- (void)test_vnode_check_setextattr_immutable_file
{
	char state = 1;
	int err = setxattr(kWormFile, kTest_attributeName, &state, sizeof(state), 0, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}

- (void)test_vnode_check_setextattr_immutable_dir
{
	char state = 1;
	int err = setxattr(kWormFile, kTest_attributeName, &state, sizeof(state), 0, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}


/* vnode_check_setextattr */
/* TODO: test cases for this api call */

/* vnode_check_setflags */
- (void)test_vnode_check_setflags_mutable_file
{
	STAssertEquals(chflags(kMutableFile, UF_HIDDEN), 0, @"retVal");
}

- (void)test_vnode_check_setflags_mutable_dir
{
	STAssertEquals(chflags(kMutableDir, UF_HIDDEN), 0, @"retVal");
}

- (void)test_vnode_check_setflags_immutable_file
{
	int err = chflags(kWormFile, UF_HIDDEN);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}

- (void)test_vnode_check_setflags_immutable_dir
{
	int err = chflags(kWormDir, UF_HIDDEN);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}


/* vnode_check_setmode */
- (void)test_vnode_check_setmode_mutable_file
{
	STAssertEquals(chmod(kMutableFile, S_IRUSR), 0, @"retVal");
	(void) chmod(kMutableFile, S_IRWXU);
}

- (void)test_vnode_check_setmode_mutable_dir
{
	STAssertEquals(chmod(kMutableDir, S_IRUSR), 0, @"retVal");
	(void) chmod(kMutableDir, S_IRWXU);
}

- (void)test_vnode_check_setmode_immutable_file
{
	int err = chmod(kWormFile, S_IRUSR);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}

- (void)test_vnode_check_setmode_immutable_dir
{
	int err = chmod(kWormDir, S_IRUSR);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}


/* vnode_check_setowner */
- (void)test_vnode_check_setowner_mutable_file
{
	STAssertEquals(chown(kMutableFile, getuid(), getgid()), 0, @"retVal");
}

- (void)test_vnode_check_setowner_mutable_dir
{
	STAssertEquals(chown(kMutableDir, getuid(), getgid()), 0, @"retVal");
}

- (void)test_vnode_check_setowner_immutable_file
{
	int err = chown(kWormFile, getuid(), getgid());
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}

- (void)test_vnode_check_setowner_immutable_dir
{
	int err = chown(kWormDir, getuid(), getgid());
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}


/* vnode_check_setutimes */
- (void)test_vnode_check_setutimes_mutable_file
{
	STAssertEquals(utimes(kMutableFile, NULL), 0, @"retVal");
}

- (void)test_vnode_check_setutimes_mutable_dir
{
	STAssertEquals(utimes(kMutableDir, NULL), 0, @"retVal");
}

- (void)test_vnode_check_setutimes_immutable_file
{
	int err = utimes(kWormFile, NULL);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}

- (void)test_vnode_check_setutimes_immutable_dir
{
	int err = utimes(kWormDir, NULL);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}


/* vnode_check_truncate */
- (void)test_vnode_check_truncate_mutable_file
{
	STAssertEquals(truncate(kMutableFile, 0), 0, @"retVal");
}

- (void)test_vnode_check_truncate_mutable_dir
{
	int err = truncate(kMutableDir, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EISDIR, @"errno");
}

- (void)test_vnode_check_truncate_immutable_file
{
	int err = truncate(kWormFile, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}

- (void)test_vnode_check_truncate_immutable_dir
{
	int err = truncate(kWormDir, 0);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EISDIR, @"errno");
}


/* vnode_check_unlink */
- (void)test_vnode_check_unlink_mutable_file
{
	STAssertEquals(unlink(kMutableFile), 0, @"retVal");
}

- (void)test_vnode_check_unlink_mutable_dir
{
	STAssertEquals(rmdir(kMutableDir), 0, @"retVal");
}

- (void)test_vnode_check_unlink_immutable_file
{
	int err = unlink(kWormFile);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}

- (void)test_vnode_check_unlink_immutable_dir
{
	int err = rmdir(kWormDir);
	STAssertEquals(err, -1, @"retVal");
	STAssertEquals(errno, EPERM, @"errno");
}


/* vnode_notify_create */
- (void)test_vnode_notify_create
{
	int state = 0;
	(void) system("touch " kWormDir "/file");
	STAssertTrue(getxattr(kWormDir "/file", kWorm_attributeName, &state, sizeof(state), 0, 0) == 1, 0, @"verify touch did add attribute; retVal");
	(void) system("mkdir " kWormDir "/dir");
	STAssertTrue(getxattr(kWormDir "/dir", kWorm_attributeName, &state, sizeof(state), 0, 0) == 1, 0, @"verify mkdir did add attribute; retVal");
	(void) system("ln " kWormDir "/file " kWormDir "/hardlink");
	STAssertTrue(getxattr(kWormDir "/hardlink", kWorm_attributeName, &state, sizeof(state), 0, 0) == 1, 0, @"verify ln did add attribute; retVal");
	(void) system("ln -s " kWormDir "/file " kWormDir "/softlink");
	STAssertTrue(getxattr(kWormDir "/softlink", kWorm_attributeName, &state, sizeof(state), 0, 0) == 1, 0, @"verify ln -s did add attribute; retVal");
}
@end
