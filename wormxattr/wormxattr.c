//
//  wormxattr.c
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


#include <sys/systm.h>
#include <mach/mach_types.h>
#include <sys/sysctl.h>
#include <libkern/OSKextLib.h>

#include "wormxattr.h"
#include "audit.h"
#include "dbg.h"

#include "wormxattr_vnode.h"

// header includes, structure predefines to make mac_policy warning free
struct socket;
struct sockopt;
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/vnode.h>
#include <security/mac_policy.h>


/*
 * Description
 * 
 * This mac policy provides the concept of write one, read many (WORM) vnodes.  
 * The WORM'ness of a vnode is represented by the presence of the extended 
 * attribute k_wormattr_xattr on a vnode.  
 *
 * Behaviour: 
 *  - if the vnode is a directory; WORM implies that its children can't be deleted
 *    i.e. no vnodes within can be moved/unlinked.  Any new vnodes created within the
 *    WORM directory inherit the WORM xattr and thus behave as specified here.
 *
 *  - if the vnode is not a directory; WORM implies that once the xattr is applied,
 *    and any open file descriptors closed, the contents of the vnode, its attributes and 
 *    xattrs can't be changed e.g. file contents, date, time, owner, xattrs
 *
 * This behaviour applies to all users; with the exception that the su can delete the 
 * k_wormattr_xattr xattr - making the file mutable and thus normal behavious returns
 */


/*
 * Policy defines; strings MUST be static
 */

#define k_wormxattr_policy_fullname		"Enforces WORM behaviour on vnodes with the " k_wormxattr_xattr " extended attribute"
#define k_label_name					k_wormxattr_xattr


/*
 * Definitions
 */

kern_return_t com_mountainstorm_kext_wormxattr_start(kmod_info_t* ki, void* data);
kern_return_t com_mountainstorm_kext_wormxattr_stop(kmod_info_t* ki, void* data);

/**
 * @brief	The policy structure infomation; everything which needs to be global
 *
 * @field	handle			the mac policy handle; used to unregister
 * @field	conf			the mac policy configuration structure
 * @field	ops				the mac ops (hook functions) structure
 * @field	labelSlot		the label slot used for our labels
 */
typedef struct __wormxattr_t {
	mac_policy_handle_t		handle;
	struct mac_policy_conf	conf;
	struct mac_policy_ops	ops;
	int						label_slot;
} wormxattr_t;


// static (global) instance
static wormxattr_t g_wormxattr_policy = {0};

static void initialize_policy(wormxattr_t* self);

static mpo_policy_init_t policy_init;


/*
 * Implementation
 */

/**
 * @brief	start method for kernel extension; where execution begins when extension is loaded
 *
 * @param	ki		kernel mod structure which represents this extension
 * @param	data	data
 *
 * @return	KERN_SUCCESS on success, else a valid kern_return_t error
 */
kern_return_t com_mountainstorm_kext_wormxattr_start(kmod_info_t* ki, void* data) {
	kern_return_t retval = KERN_FAILURE;
	
	initialize_policy(&g_wormxattr_policy);
	retval = (kern_return_t) mac_policy_register(&g_wormxattr_policy.conf, 
												 &g_wormxattr_policy.handle, 
												 data);
	if (retval != KERN_SUCCESS) {
		audit_log("Failed to register mac policy: %d\n", retval);
	} else {
		dbg_info("Label slot assigned: %d\n", g_wormxattr_policy.label_slot);
	}
	return retval;
}


/**
 * @brief	stop method for kernel extension; where execution begins when extension is unloaded
 *
 * @param	ki		kernel mod structure which represents this extension
 * @param	data	data
 *
 * @return	KERN_SUCCESS on success, else a valid kern_return_t error
 */
kern_return_t com_mountainstorm_kext_wormxattr_stop(kmod_info_t* ki, void* data) {
	dbg_info("unregistering security policy\n");
	kern_return_t retval = KERN_SUCCESS; // default to success 
#ifdef DEBUG
	// release version denys unregister; only unload in debug version
	retval = mac_policy_unregister(g_wormxattr_policy.handle);
	if (retval != KERN_SUCCESS) {
		dbg_error("Failed to unregister mac policy: %d\n", retval);
	}
#endif
	return retval;
}


/**
 * @brief	sets the WORM state in a label
 *
 * @param	label	the label to set the state in
 * @param	state	the state to set; 0 mutable, anything else WORM
 */
__private_extern__ inline void wormxattr_set_label(struct label* label, int state) {
	if (label) {
		mac_label_set(label, g_wormxattr_policy.label_slot, (intptr_t) state);	
	}
}


/**
 * @brief	gets the WORM state from a label
 *
 * @param	label	the label to get the state from
 *
 * @return	the value of the WORM state; 0 mutable, anything else WORM
 */
__private_extern__ inline int wormxattr_get_label(struct label* label) {
	int retval = 0;
	if (label) {
		retval = (int) mac_label_get(label, g_wormxattr_policy.label_slot);
	}
	return retval;
}


/**
 * @brief	initialize the mac policy structures with our hooks
 *
 * @param	self	the structure to initialize
 */
static void initialize_policy(wormxattr_t* self) {
	static const char* labelNamespaces[] = {k_label_name}; // must be static
	(void) memset(self, 0x00, sizeof(*self));
	
	// init policy configuration
	self->conf.mpc_name = OSKextGetCurrentIdentifier();
	self->conf.mpc_fullname = k_wormxattr_policy_fullname;
	self->conf.mpc_labelnames = (const char**) labelNamespaces;
	self->conf.mpc_labelname_count = sizeof(labelNamespaces)/sizeof(labelNamespaces[0]);
	self->conf.mpc_ops = &self->ops;
#ifdef DEBUG
	// debug version should allow loading post boot and unloading
	self->conf.mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK;
#else 
	// release version should load early in boot process (to enact policy) and deny unload
	// this will cause us to load very early in the boot phase (pre bsd subsystem) and
	// thus we can be sure that ALL vnodes will have a label and we'll get a notify for all of them
	self->conf.mpc_loadtime_flags = MPC_LOADTIME_FLAG_NOTLATE;
#endif
	self->conf.mpc_field_off = &self->label_slot;
	self->conf.mpc_runtime_flags = 0;
	self->conf.mpc_data = NULL;

	// init policy hooks
	self->ops.mpo_policy_init = policy_init;
	wormxattr_vnode_initialize(&self->ops);
}


// mac hooks
static void policy_init(struct mac_policy_conf *mpc) {
	/*
	 * We'd like to enable vnode labeling here but the sysctl for it "security.mac.labelvnodes"
	 * doesn't support access from kernel mode (strangely) e.g. CTLFLAG_KERN.  As such we can't
	 * and will instead do it through  /etc/sysctl.conf.  This means that SOME vnodes 
	 * will exist from before this was enabled (sysctl.conf is processed relativly late in the 
	 * boot process.  As such we handle NULL labels by just ignoring it and returning "grant" 
	 * for those operations.
	 *
	 * Note: this means that you cant make directories/files WORM whose vnodes are
	 * created before sysctl.conf is processed.
	 */
}

