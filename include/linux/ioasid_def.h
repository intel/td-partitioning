#ifndef __LINUX_IOASID_DEF_H
#define __LINUX_IOASID_DEF_H
typedef unsigned int ioasid_t;

#define INVALID_IOASID ((ioasid_t)-1)
#if IS_ENABLED(CONFIG_IOASID)
static inline bool pasid_valid(ioasid_t ioasid)
{
	return ioasid != INVALID_IOASID;
}
void __ioasid_put(ioasid_t ioasid);
#else /* !CONFIG_IOASID */
static inline bool pasid_valid(ioasid_t ioasid)
{
	return false;
}
#endif /* !CONFIG_IOASID */
#endif /* __LINUX_IOASID_H */
