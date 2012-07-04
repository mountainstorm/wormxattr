wormxattr
---------
A simple mach security policy extension which provides WORM (Write Once, Read Many) functionality.  It makes use of vnode labels, which need to be enabled as early in the boot process as possible.  To help you can stick the sysctl.conf file in /etc, install the driver and reboot.

To use, create a new directory and set the extended attribute "com.mountainstorm.Worm".  Once this is done you can create files in the directory and read/write whilst you have that file handle open.  Once you close the file handle you can only read (you can remove the xattr though)

wormxattr_test is a otest library which has a set of unit test to validate that the drivers working.


Issues
------
You may have a small issue in loading the driver (have a look in Console.app and look at messages from the early boot process - when other policy/sandbox drivers are loaded).

This is due to a hack I use to get loaded very very early in the boot process.  OSX does a check against the copyright string etc before loading the driver.  This code may have changed from when I wrote this.  As such you can just remove the AppleSecurityExtension key from the kext's plist.

Note: this is from memory, it was 6 months ago I wrote this ... if that doesn;t work send me a message.


License (MIT style)
-------------------
Copyright (c) 2012 Mountainstorm

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.