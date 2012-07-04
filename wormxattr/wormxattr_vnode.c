//
//  wormxattr_vnode.c
//  wormxattr
//
//  Created by R J Cooper on 22/10/2011.
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

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <sys/unistd.h>
#include <sys/fcntl.h>

#include "wormxattr.h"
#include "wormxattr_vnode.h"
#include "dbg.h"
#include "audit.h"


// header includes, structure predefines to make mac_policy warning free
struct socket;
struct sockopt;
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/vnode.h>
#include <security/mac_policy.h>


/*
 * Definitions
 */

static inline int get_worm_xattr(struct vnode* vp);

// mac vnode hooks
static mpo_vnode_check_access_t				vnode_check_access;
static mpo_vnode_check_deleteextattr_t		vnode_check_deleteextattr;
static mpo_vnode_check_exchangedata_t		vnode_check_exchangedata;
static mpo_vnode_check_open_t				vnode_check_open;
static mpo_vnode_check_rename_from_t		vnode_check_rename_from;
static mpo_vnode_check_select_t				vnode_check_select;
static mpo_vnode_check_setattrlist_t		vnode_check_setattrlist;
static mpo_vnode_check_setextattr_t			vnode_check_setextattr;
static mpo_vnode_check_setflags_t			vnode_check_setflags;
static mpo_vnode_check_setmode_t			vnode_check_setmode;
static mpo_vnode_check_setowner_t			vnode_check_setowner;
static mpo_vnode_check_setutimes_t			vnode_check_setutimes;
static mpo_vnode_check_truncate_t			vnode_check_truncate;
static mpo_vnode_label_associate_extattr_t	vnode_label_associate_extattr;
static mpo_vnode_label_copy_t				vnode_label_copy;
static mpo_vnode_label_destroy_t			vnode_label_destroy;
static mpo_vnode_label_recycle_t			vnode_label_recycle;
static mpo_vnode_check_unlink_t				vnode_check_unlink;
static mpo_vnode_label_update_extattr_t		vnode_label_update_extattr;
static mpo_vnode_notify_create_t			vnode_notify_create;
static mpo_vnode_notify_rename_t			vnode_notify_rename;


/*
 * Implementation
 */

/**
 * @brief	initializes the vnode callbacks hooked by this policy.
 *			Note: this ONLY sets fields which begin with mpo_vnode
 *
 * @param	ops		the policy ops to set our hooks into.
 */
__private_extern__ void wormxattr_vnode_initialize(struct mac_policy_ops* ops) {
	if (ops) {
		ops->mpo_vnode_check_access				= vnode_check_access;
		ops->mpo_vnode_check_deleteextattr		= vnode_check_deleteextattr;
		ops->mpo_vnode_check_exchangedata		= vnode_check_exchangedata;
		// we're not hooking ioctl as we'd get into a world of vnode specific hurt
		ops->mpo_vnode_check_open				= vnode_check_open;
		ops->mpo_vnode_check_rename_from		= vnode_check_rename_from;
		ops->mpo_vnode_check_setattrlist		= vnode_check_setattrlist;
		ops->mpo_vnode_check_setextattr			= vnode_check_setextattr;
		ops->mpo_vnode_check_setflags			= vnode_check_setflags;
		ops->mpo_vnode_check_setmode			= vnode_check_setmode;
		ops->mpo_vnode_check_setowner			= vnode_check_setowner;
		ops->mpo_vnode_check_setutimes			= vnode_check_setutimes;
		ops->mpo_vnode_check_truncate			= vnode_check_truncate;
		ops->mpo_vnode_label_associate_extattr	= vnode_label_associate_extattr;
		ops->mpo_vnode_label_copy				= vnode_label_copy;
		ops->mpo_vnode_label_destroy			= vnode_label_destroy;
		ops->mpo_vnode_label_recycle			= vnode_label_recycle;
		ops->mpo_vnode_check_unlink				= vnode_check_unlink;
		// we won't hook write (with its performance hit) as we prevent opening with write
		ops->mpo_vnode_label_update_extattr		= vnode_label_update_extattr;
		ops->mpo_vnode_notify_create			= vnode_notify_create;
		ops->mpo_vnode_notify_rename			= vnode_notify_rename;
		/*
		 * We're not hooking any of the labeling callbacks to allow
		 * relabeling from userspace; update/internalize/externalize etc
		 * primarilly as we don't want to allow changing of labels from
		 * userspace by any method other than setting/deleting the extended attr.
		 *
		 * Its also hard to know exactly how/why these calls would be used as 
		 * there apple private :(
		 */
	} else {
		panic("Invalid parameter - ops == NULL\n"); 
	}
}


/**
 * @brief	checks if the vnode has our extended attribute set
 *			Note: if an error occurs and we are unable to retrieve the xattr
 *			this call will return zero (mutable).  This is due to this functions 
 *			intended usage; in which an error is not a viable return
 *				
 * @param	vnode		the vnode to evaluate
 *
 * @return	0 if mutable; non zero for WORM
 */
static inline int get_worm_xattr(struct vnode* vp) {
	int retval = 0; // mutable
	
	char state = 0;
	size_t attrlen = 0;
	int ret = mac_vnop_getxattr(vp, k_wormxattr_xattr, &state, sizeof(state), &attrlen);
	if (	(ret == KERN_SUCCESS) 
		 || (ret == ERANGE)) {
		// we dont care that the attribute is to large ... its there
		retval = 1; // immutable
	}
	return retval;
}


// mac hooks - see mac_policy for documentation
static int vnode_check_access(kauth_cred_t cred,
							  struct vnode *vp,
							  struct label *label,
							  int acc_mode) {
	int retval = 0; // grant access
	if (wormxattr_get_label(label)) {
		if (vnode_isdir(vp) == 0) {
			/*
			 * Note: contary to the documentation for mpo_vnode_check_access_t
			 * acc_mode does not contain the access(2) flags.  It is instead being
			 * converted into V{READ,WRITE,EXEC} modes.
			 */
			if (acc_mode & VWRITE) {
				// we dont need to audit people testing what access they have
				retval = EPERM; // permision denied
			}
		}
	}
	return retval;
}


static int vnode_check_deleteextattr(kauth_cred_t cred,
									 struct vnode *vp,
									 struct label *vlabel,
									 const char *name) {
	int retval = 0; // grant access
	if (wormxattr_get_label(vlabel)) {
		if (kauth_cred_getuid(cred) != 0) {
			// normal users can't remove anything if it's immutable
			audit_deny(cred, "Extended attribute, %s, prevents deletion of attributes by non su\n", k_wormxattr_xattr);
			retval = EPERM;
		}
	}
	return retval;
}


static int vnode_check_exchangedata(kauth_cred_t cred,
									struct vnode *v1,
									struct label *vl1,
									struct vnode *v2,
									struct label *vl2) {
	int retval = 0; // grant access
	if (	wormxattr_get_label(vl1) 
		 || wormxattr_get_label(vl2)) {
		// you can't swap anything into one of our files
		audit_deny(cred, "Extended attribute, %s, on vnode prevents exchanging data\n", k_wormxattr_xattr);
		retval = EPERM; // permision denied		
	}
	return retval;
}


static int vnode_check_open(kauth_cred_t cred,
							struct vnode *vp,
							struct label *label,
							int acc_mode) {
	int retval = 0; // grant access
	if (wormxattr_get_label(label)) {
#ifdef DEBUG
		char buf[MAXPATHLEN] = {0};
		int len = MAXPATHLEN;
		(void) vn_getpath(vp, buf, &len);
		
		dbg_info("Opening WORM file - %s; checking mode - %x\n", buf, acc_mode);
#endif
		// deny if its not a directory and any of the write flags are set
		if (vnode_isdir(vp) == 0) {
			if (	(OFLAGS(acc_mode) & O_WRONLY)
				 || (OFLAGS(acc_mode) & O_RDWR)
				 || (acc_mode & O_APPEND)
				 || (acc_mode & O_TRUNC)) {
				audit_deny(cred, "Extended attribute, %s, on vnode prevents opening with write access (mode = %x)\n", k_wormxattr_xattr, acc_mode);
				retval = EPERM; // permision denied
			}
		}
	}
	return retval;
}


static int vnode_check_rename_from(kauth_cred_t cred,
								   struct vnode *dvp,
								   struct label *dlabel,
								   struct vnode *vp,
								   struct label *label,
								   struct componentname *cnp) {
	int retval = 0; // grant access
	// you can't move any files from a WORM directory; it would change the dir contents
	if (wormxattr_get_label(dlabel)) {
		// vnode is immutable - you cant change it, and that includes its name!
		audit_deny(cred, "Extended attribute, %s, on vnode prevents renaming\n", k_wormxattr_xattr);
		retval = EPERM; // permision denied		
	}
	return retval;
}


static int vnode_check_setattrlist(kauth_cred_t cred,
								   struct vnode *vp,
								   struct label *vlabel,
								   struct attrlist *alist) {
	int retval = 0; // grant access
	if (wormxattr_get_label(vlabel)) {
		audit_deny(cred, "Extended attribute, %s, on vnode prevents setting attributes\n", k_wormxattr_xattr);
		retval = EPERM; // permision denied
	}
	return retval;
}


static int vnode_check_setextattr(kauth_cred_t cred,
								  struct vnode *vp,
								  struct label *label,
								  const char *name,
								  struct uio *uio) {
	int retval = 0; // grant access
	if (wormxattr_get_label(label)) {
		audit_deny(cred, "Extended attribute, %s, on vnode prevents setting extended attributes\n", k_wormxattr_xattr);
		retval = EPERM; // permision denied
	}
	/* 
	 * we could have decided to recursivly set this attribute on all child elements 
	 * (if it was a dir).  Not doing that gives us both options (the user could
	 * have used "xattr -r" if thats what they wanted).  So we'll adopt the simpler
	 * and more flexible approach of not doing it.
	 *
	 * Alternativly we could check that the directory is empty before enabling the 
	 * attribute.  We've decided not to do this, as again it gives us more flexibility.
	 *
	 * Note: this does mean that not ALL files in the directory will behave WORM; only those
	 * tagged as such - which is consitent with our world view
	 */
	return retval;
}


static int vnode_check_setflags(kauth_cred_t cred,
								struct vnode *vp,
								struct label *label,
								u_long flags) {
	int retval = 0; // grant access
	if (wormxattr_get_label(label)) {
		audit_deny(cred, "Extended attribute, %s, on vnode prevents setting flags\n", k_wormxattr_xattr);
		retval = EPERM; // permision denied
	}
	return retval;
}


static int vnode_check_setmode(kauth_cred_t cred,
							   struct vnode *vp,
							   struct label *label,
							   mode_t mode) {
	int retval = 0; // grant access
	if (wormxattr_get_label(label)) {
		audit_deny(cred, "Extended attribute, %s, on vnode prevents setmode\n", k_wormxattr_xattr);
		retval = EPERM; // permision denied
	}
	return retval;
}


static int vnode_check_setowner(kauth_cred_t cred,
								struct vnode *vp,
								struct label *label,
								uid_t uid,
								gid_t gid) {
	int retval = 0; // grant access
	if (wormxattr_get_label(label)) {
		audit_deny(cred, "Extended attribute, %s, on vnode prevents changing ownership\n", k_wormxattr_xattr);
		retval = EPERM; // permision denied
	}
	return retval;
}


static int vnode_check_setutimes(kauth_cred_t cred,
								 struct vnode *vp,
								 struct label *label,
								 struct timespec atime,
								 struct timespec mtime) {
	int retval = 0; // grant access
	if (wormxattr_get_label(label)) {
		audit_deny(cred, "Extended attribute, %s, on vnode prevents setting utimes\n", k_wormxattr_xattr);
		retval = EPERM; // permision denied
	}
	return retval;
}


static int vnode_check_truncate(kauth_cred_t active_cred,
								kauth_cred_t file_cred,	/* NULLOK */
								struct vnode *vp,
								struct label *label) {
	int retval = 0; // grant access
	if (wormxattr_get_label(label)) {
		if (vnode_isdir(vp) == 0) {
			audit_deny(active_cred, "Extended attribute, %s, on vnode prevents truncate\n", k_wormxattr_xattr);
			retval = EPERM; // permision denied
		}
	}
	return retval;
}


static int vnode_label_associate_extattr(struct mount *mp,
										 struct label *mntlabel,
										 struct vnode *vp,
										 struct label *vlabel) {
	/*
	 * this is called when a vnode is created for an existing file
	 * load check for an extended attribute and if its present set our label
	 */
	if (get_worm_xattr(vp)) {
#ifdef DEBUG
		char buf[MAXPATHLEN] = {0};
		int len = MAXPATHLEN;
		(void) vn_getpath(vp, buf, &len);
		
		dbg_info("vnode created for existing file; setting label to reflect - %s\n", buf);
#endif
		wormxattr_set_label(vlabel, 1);
	}
	return 0; // grant access
}


static void vnode_label_copy(struct label *src,
							 struct label *dest) {
	wormxattr_set_label(dest, wormxattr_get_label(src));	
}


static void vnode_label_destroy(struct label *label) {
	wormxattr_set_label(label, 0); // cleanup just to be a nice citizen
}


static void vnode_label_recycle(struct label *label) {
	// cleanup WORM state that new user of the label gets it properly initialized
	wormxattr_set_label(label, 0); 
}


static int vnode_check_unlink(kauth_cred_t cred,
							  struct vnode *dvp,
							  struct label *dlabel,
							  struct vnode *vp,
							  struct label *label,
							  struct componentname *cnp) {
	int retval = 0; // grant access
	// file must be mutable (as we're destorying its contents, and dir must be mutable as we're changing its contents
	if (	wormxattr_get_label(dlabel)
		 || wormxattr_get_label(label)) {
		audit_deny(cred, "Extended attribute, %s, on vnode prevents unlink\n", k_wormxattr_xattr);
		retval = EPERM; // permision denied
	}
	return retval;
}


static int vnode_label_update_extattr(struct mount *mp,
									  struct label *mntlabel,
									  struct vnode *vp,
									  struct label *vlabel,
									  const char *name) {
	if (strcmp(name, k_wormxattr_xattr) == 0) {
		// our attribute was chaned (set/delete) - change label to reflect attribute state
		wormxattr_set_label(vlabel, get_worm_xattr(vp));
	}
	return 0; // success - according to the docs 
}


static int vnode_notify_create(kauth_cred_t cred,
							   struct mount *mp,
							   struct label *mntlabel,
							   struct vnode *dvp,
							   struct label *dlabel,
							   struct vnode *vp,
							   struct label *vlabel,
							   struct componentname *cnp) {
	int retval = 0; // grant access
	/*
	 * this is called when a vnode is created for a file which has just been created
	 * if our parent has our attribute we'll inherit it to the new child )and its label)
	 */
	if (wormxattr_get_label(dlabel)) {
		char state = 1;

		// parent directory is WORM so inherit permission to newly created vnode
		dbg_info("parent directory vnode is labeled as WORM; setting label to reflect - %s\n", cnp->cn_nameptr);
		
		retval = mac_vnop_setxattr(vp, k_wormxattr_xattr, &state, sizeof(state));
		if (retval == KERN_SUCCESS) {
			// success - set WORM in label
			wormxattr_set_label(vlabel, 1); 
		} else {
			// oops, error - retval will be the error from setxattr
			audit_deny(cred, "Extended attribute, %s, could not be inherited\n", k_wormxattr_xattr);
		}
	}
	return retval;	
}


static void vnode_notify_rename(kauth_cred_t cred,
								struct vnode *vp,
								struct label *label,
								struct vnode *dvp,
								struct label *dlabel,
								struct componentname *cnp) {
	if (wormxattr_get_label(dlabel)) {
		char state = 1;
		
		// parent directory is WORM so inherit permission to newly created vnode
		dbg_info("parent directory vnode is labeled as WORM; setting label to reflect - %s\n", cnp->cn_nameptr);
		
		if (mac_vnop_setxattr(vp, k_wormxattr_xattr, &state, sizeof(state)) == KERN_SUCCESS) {
			// success - set WORM in label
			wormxattr_set_label(label, 1); 
		} else {
			/*
			 * oops, error - we can't set attribute.  Unfortunatly we can't tell it not to rename (its done)
			 * worse still we can't do this in the rename_to hook as vp can be NULL.  As such the best we can
			 * do is panic or log an error and accept that this new file isn't marked WORM.
			 *
			 * as panicing is generally bad and the file which has already been created will not 
			 * have WORM set, even if we do, we'll just log the error and accept it
			 *
			 * The only time I've seen this is for items which CAN'T have xattrs applied i.e. fifo's
			 */
			audit_deny(cred, "Extended attribute, %s, could not be inherited\n", k_wormxattr_xattr);
		}
	}

}
