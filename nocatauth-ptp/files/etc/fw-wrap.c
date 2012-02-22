/*
 * nc-iptables.c
 * setuid wrapper for nocat to run iptables
 *
 * change ALLOWEDUID to the uid of ${nocat-user}
 * $(CC) -O -o nc-iptables nc-iptables.c
 * chown root nc-iptables;chgrp ${nocat-group} nc-iptables;
 * chmod 4110 nc-iptables
 *
 * 17.july.2002 brian.s.walden nc-iptables@cuzuco.com
 */

# include <stdio.h>
# include <unistd.h>
# include <pwd.h>
# include <sys/types.h>

/* # define ALLOWED_UID    "nocat" */
/* # define FW_BINARY	   "/sbin/iptables" */
# define ROOT_UID	0

static char *smallenv[] = {
    "PATH=/sbin:/bin:/usr/bin",
    NULL
};

int main(int argc, char **argv)
{
    struct passwd *allowed;
    uid_t actual;

    /* Get the UID of the requested user. */
    allowed = getpwnam( ALLOWED_UID );
    if ( allowed == NULL ) {
	fprintf( stderr, "%.255s: Can't find UID %.255s\n", argv[0], ALLOWED_UID );
	exit(253);
    }

    /* Get the UID of the current process. */
    actual = getuid();

    if (actual == allowed->pw_uid) {
	/* Stash the original program name */
	char *oldargv0 = argv[0];
	int e_errno;
	char buf[1024];
	extern int errno;

	/* Now we're going to be the firewall binary. */
	argv[0] = FW_BINARY;

	/* By the power of Greyskull... */
	setuid(ROOT_UID);

	/* Make it so. */
	execve(argv[0], &argv[0], smallenv);

	/* If we're here, something horked. */
	e_errno = errno;
	setuid(actual);
	sprintf(buf, "%.255s: %.255s", oldargv0, argv[0]);
	errno = e_errno;
	perror(buf);
	exit(255);
    }

    setuid(actual);
    fprintf(stderr, "%.255s: Permission denied\n", argv[0]);
    exit(254);
}
