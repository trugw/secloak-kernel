#ifndef ERRNO_H
#define ERRNO_H

/* Copied from include/uapi/asm-generic/errno-base.h in Linux kernel */
#ifndef EIO
#define EIO    5  /* I/O error */
#endif

#ifndef ENOMEM
#define ENOMEM    12  /* Out of memory */
#endif

#ifndef EBUSY
#define EBUSY   16  /* Device or resource busy */
#endif

#ifndef EINVAL
#define EINVAL    22  /* Invalid argument */
#endif

// cf. also newlib/libc/include/sys/errno.h
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL   125 /* Address not available */
#endif

#endif

