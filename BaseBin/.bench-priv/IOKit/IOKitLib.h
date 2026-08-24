#ifndef BENCH_IOKITLIB_H
#define BENCH_IOKITLIB_H
#include <IOKit/IOTypes.h>
#include <CoreFoundation/CoreFoundation.h>
#define kIOMainPortDefault ((mach_port_t)0)
#define kIOMasterPortDefault ((mach_port_t)0)
CFMutableDictionaryRef IOServiceMatching(const char *name);
CFMutableDictionaryRef IOServiceNameMatching(const char *name);
mach_port_t IOServiceGetMatchingService(mach_port_t mp, CFDictionaryRef m);
IOReturn IOServiceGetMatchingServices(mach_port_t mp, CFDictionaryRef m, io_iterator_t *it);
IOReturn IOServiceOpen(io_service_t s, task_t t, uint32_t type, io_connect_t *c);
IOReturn IOServiceClose(io_connect_t c);
IOReturn IOConnectCallMethod(io_connect_t c, uint32_t sel, const uint64_t *in, uint32_t inc, const void *is, size_t isc, uint64_t *o, uint32_t *oc, void *os, size_t *osc);
IOReturn IOConnectCallScalarMethod(io_connect_t c, uint32_t sel, const uint64_t *in, uint32_t inc, uint64_t *o, uint32_t *oc);
IOReturn IOConnectCallStructMethod(io_connect_t c, uint32_t sel, const void *is, size_t isc, void *os, size_t *osc);
IOReturn IOConnectCallAsyncMethod(io_connect_t c, uint32_t sel, mach_port_t wake, uint64_t ref, uint32_t refc, const uint64_t *in, uint32_t inc, const void *is, size_t isc, uint64_t *o, uint32_t *oc, void *os, size_t *osc);
IOReturn IOConnectCallAsyncScalarMethod(io_connect_t c, uint32_t sel, mach_port_t wake, uint64_t ref, uint32_t refc, const uint64_t *in, uint32_t inc, uint64_t *o, uint32_t *oc);
IOReturn IOConnectCallAsyncStructMethod(io_connect_t c, uint32_t sel, mach_port_t wake, uint64_t ref, uint32_t refc, const void *is, size_t isc, void *os, size_t *osc);
IOReturn IOConnectAddClient(io_connect_t c, io_connect_t s);
IOReturn IOConnectAddRef(io_connect_t c);
IOReturn IOConnectGetService(io_connect_t c, io_service_t *s);
IOReturn IOConnectMapMemory(io_connect_t c, uint32_t t, task_t tk, mach_vm_address_t *a, mach_vm_size_t *sz, uint32_t fl);
IOReturn IOConnectUnmapMemory(io_connect_t c, uint32_t t, task_t tk, mach_vm_address_t a);
IOReturn IOConnectRelease(io_connect_t c);
IOReturn IOConnectSetCFProperties(io_connect_t c, CFTypeRef p);
IOReturn IOConnectSetNotificationPort(io_connect_t c, uint32_t t, mach_port_t p, uintptr_t r);
kern_return_t IOConnectTrap(io_connect_t c, uint32_t idx, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6);
IOReturn IOObjectRelease(io_object_t o);
IOReturn IOObjectRetain(io_object_t o);
IOReturn IOObjectGetClass(io_object_t o, io_name_t n);
IOReturn IOObjectGetRetainCount(io_object_t o, uint32_t *rc);
IOReturn IOObjectGetKernelRetainCount(io_object_t o, uint32_t *rc);
boolean_t IOObjectConformsTo(io_object_t o, const io_name_t n);
CFTypeRef IORegistryEntryCreateCFProperty(mach_port_t e, CFStringRef k, CFAllocatorRef al, uint32_t opt);
IOReturn IORegistryEntryCreateCFProperties(mach_port_t e, CFMutableDictionaryRef **p, CFAllocatorRef al, uint32_t opt);
IOReturn IORegistryEntrySetCFProperties(mach_port_t e, CFTypeRef p);
#define kIORegistryEntryPropertyKeysKey "IORegistryEntryPropertyKeys"
IOReturn IORegistryEntryGetProperty(mach_port_t e, const io_name_t n, void *b, uint32_t *l);
IOReturn IORegistryEntryGetName(mach_port_t e, io_name_t n);
IOReturn IORegistryEntryGetPath(mach_port_t e, const io_name_t n, io_string_t p);
IOReturn IORegistryEntryGetRegistryEntryID(mach_port_t e, uint64_t *id);
IOReturn IORegistryGetRootEntry(mach_port_t mp, io_registry_entry_t *r);
IOReturn IORegistryEntryFromPath(mach_port_t mp, const io_string_t p);
IOReturn IORegistryCreateIterator(mach_port_t mp, const io_name_t n, uint32_t opt, io_iterator_t *it);
IOReturn IORegistryEntryCreateIterator(mach_port_t e, const io_name_t n, uint32_t opt, io_iterator_t *it);
IOReturn IORegistryEntryGetChildIterator(mach_port_t e, const io_name_t n, io_iterator_t *it);
IOReturn IORegistryEntryGetParentIterator(mach_port_t e, const io_name_t n, io_iterator_t *it);
io_object_t IOIteratorNext(io_iterator_t it);
IOReturn IORegistryIterateRecursively(void); /* placeholder */
IOReturn IORegistryIterateParents(void); /* placeholder */
IOReturn IOServiceGetAuthorizationID(io_service_t s, uint32_t *a);
IOReturn IOServiceSetAuthorizationID(io_service_t s, uint32_t a);
IOReturn IOServiceGetBusyStateAndTime(io_service_t s, uint32_t *st, uint32_t *bs, uint64_t *bt);
#endif
