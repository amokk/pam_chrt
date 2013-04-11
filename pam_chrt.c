#define USER_FILE "/root/myfile"


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <pwd.h>
#include <string.h>
#include <ctype.h>


#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#define PAM_DEBUG_ARG       0x0001

static int
_pam_parse (const pam_handle_t *pamh, int argc, const char **argv) {
    int ctrl=0;

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv) {

	/* generic options */

	if (!strcmp(*argv,"debug"))
	    ctrl |= PAM_DEBUG_ARG;
	else {
	    pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
	}
    }

    return ctrl;
}

static int perform_check (pam_handle_t *pamh, int ctrl, const char *function_name) {
    int retval = PAM_AUTH_ERR;
    const char *username;
    char fileline[256];
    struct passwd *user_pwd;
    FILE *userfile;

    // ktory user sa prihlasil ?
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS || username == NULL) {
        pam_syslog(pamh, LOG_WARNING, "cannot determine username");
        return (retval == PAM_CONV_AGAIN ? PAM_INCOMPLETE:PAM_SERVICE_ERR);
    }

    // dostan vsetky info o userovi z /etc/passwd (ne-chroot) ak user je root tak dalej necheckuj
    user_pwd = pam_modutil_getpwnam(pamh, username);
    if (user_pwd->pw_uid == 0) {
    	return PAM_SUCCESS;
    }

    // otvor nas subor a zisti v cykle ci user ktory sa prihlasil je v subore
    userfile = fopen(USER_FILE,"r");
    if (userfile == NULL) { /* Check that we opened it successfully */
    	pam_syslog(pamh, LOG_ERR, "Error opening %s: %m", USER_FILE);
    	return PAM_SERVICE_ERR;
    }

    retval = 1;

    while ((fgets(fileline, sizeof(fileline)-1, userfile) != NULL) && retval) {
    	if (fileline[strlen(fileline) - 1] == '\n')
    		fileline[strlen(fileline) - 1] = '\0';
    	retval = strcmp(fileline, username);


    	//retval = ( strcmp(ttyfileline, uttyname) && (!ptname[0] || strcmp(ptname, uttyname)) );


    }
    fclose(userfile);

    if (retval != 0) {
	    pam_syslog(pamh, LOG_WARNING, "access denied: '%s' is not in file !", username);

	    retval = PAM_AUTH_ERR;

	    // ak sme nenasli usera v /etc/passwd tak return PAM_USER_UNKNOWN
	    if (user_pwd == NULL) {
	    	retval = PAM_USER_UNKNOWN;
	    }
    } else {
    	if (ctrl & PAM_DEBUG_ARG) {
    		pam_syslog(pamh, LOG_DEBUG, "access allowed for '%s'", username);
    	}

    	retval = PAM_SUCCESS;
    }

    return retval;
}

/* --- authentication management functions --- */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ctrl;

    /* parse the arguments */
    ctrl = _pam_parse (pamh, argc, argv);

    return perform_check(pamh, ctrl, __FUNCTION__);
}

PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN int pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ctrl;

    /* parse the arguments */
    ctrl = _pam_parse (pamh, argc, argv);

    /* take the easy route */
    return perform_check(pamh, ctrl, __FUNCTION__);
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_securetty_modstruct = {
     "pam_chrt",
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     NULL,
     NULL,
     NULL,
};

#endif /* PAM_STATIC */

/* end of module definition */
