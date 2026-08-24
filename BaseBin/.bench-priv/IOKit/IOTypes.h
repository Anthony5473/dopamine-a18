#ifndef BENCH_IOTYPES_H
#define BENCH_IOTYPES_H
#include <mach/mach_types.h>
#include <stdint.h>
typedef kern_return_t IOReturn;
typedef mach_port_t io_object_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_service_t;
typedef io_object_t io_iterator_t;
typedef io_object_t io_registry_entry_t;
typedef char io_name_t[128];
typedef char io_string_t[512];
#define IO_OBJECT_NULL ((io_object_t)0)
#define IO_OBJECT_NULL_PTR ((io_object_t *)0)
#define kIOReturnSuccess ((IOReturn)0)
#define kIOMapWriteCombineCache (0x00000001)
#define kIOMapInhibitCache      (0x00000100)
#define kIOMapWriteThruCache    (0x00000200)
#define kIOMapCopybackCache     (0x00000400)
#define kIOMapReadOnly          (0x00001000)
#define kIOMapDefaultCache      (0)
#define kIOReturnBadMedia       ((IOReturn)0x2c5)
#define kIOReturnUnsupported    ((IOReturn)0x2c6)
#endif
