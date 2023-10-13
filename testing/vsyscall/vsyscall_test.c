#include <stdio.h>
#include <sys/time.h>
#include <errno.h>

typedef long (*gettimeofday_t)(struct timeval *tv, struct timezone *tz);

int main()
{
	int rc;
	struct timeval now ={.tv_sec=0, .tv_usec=0};

	/* Using Glibc function - should always pass */
	printf("\nAttempting glibc gettimeofday()\n");
	rc=gettimeofday(&now, NULL);
	if(rc==0) {
		printf("gettimeofday() successful.\n");
		printf("time = %lu.%lu\n", now.tv_sec, now.tv_usec);
	} else {
		printf("gettimeofday() failed, errno = %d\n", errno);
	}

	/* Use vsyscall API in execute (XONLY) mode - should always pass */
	printf("\nAttempting vsys_gettimeofday() execute\n");
	gettimeofday_t vsys_gettimeofday = (gettimeofday_t)(0xffffffffff600000);
	rc=vsys_gettimeofday(&now, NULL);

	printf("vsys_gettimeofday execute rc: %d\n", rc);
	if(rc==0) {
		printf("vsys_gettimeofday() xonly successful.\n");
		printf("time = %lu.%lu\n", now.tv_sec, now.tv_usec);
	} else {
		printf("vsys_gettimeofday() failed, errno = %d\n", errno);
	}

	/*
	 * Directly read the vsyscall page
	 * - Test should fail (#GP) with LASS enabled.
	 * - Test should pass with vsyscall=emulate command line parameter
	 *   which disables kernel LASS enforcement.
	 */
	printf("\nAttempting direct read of vsys_gettimeofday\n");
	rc = *(int*)(vsys_gettimeofday);
	printf("vsys_gettimeofday() emulate successful read rc: %d\n", rc);

	return 0;
}
