#line 1 "lsd.x"
#import <Foundation/Foundation.h>
#import <libjailbreak/util.h>
#import <libroot.h>


#include <substrate.h>
#if defined(__clang__)
#if __has_feature(objc_arc)
#define _LOGOS_SELF_TYPE_NORMAL __unsafe_unretained
#define _LOGOS_SELF_TYPE_INIT __attribute__((ns_consumed))
#define _LOGOS_SELF_CONST const
#define _LOGOS_RETURN_RETAINED __attribute__((ns_returns_retained))
#else
#define _LOGOS_SELF_TYPE_NORMAL
#define _LOGOS_SELF_TYPE_INIT
#define _LOGOS_SELF_CONST
#define _LOGOS_RETURN_RETAINED
#endif
#else
#define _LOGOS_SELF_TYPE_NORMAL
#define _LOGOS_SELF_TYPE_INIT
#define _LOGOS_SELF_CONST
#define _LOGOS_RETURN_RETAINED
#endif

__asm__(".linker_option \"-framework\", \"CydiaSubstrate\"");




#line 5 "lsd.x"
__unused static NSURL * (*_logos_orig$_ungrouped$_LSGetInboxURLForBundleIdentifier)(NSString *bundleIdentifier); __unused static NSURL * _logos_function$_ungrouped$_LSGetInboxURLForBundleIdentifier(NSString *bundleIdentifier)
{
	NSURL *origURL = _logos_orig$_ungrouped$_LSGetInboxURLForBundleIdentifier(bundleIdentifier);
	if (![bundleIdentifier hasPrefix:@"com.apple"] && [origURL.path hasPrefix:@"/var/mobile/Library/Application Support/Containers/"]) {
		return [NSURL fileURLWithPath:JBROOT_PATH_NSSTRING(origURL.path)];
	}
	return origURL;
}

__unused static int (*_logos_orig$_ungrouped$_LSServer_RebuildApplicationDatabases)(); __unused static int _logos_function$_ungrouped$_LSServer_RebuildApplicationDatabases()
{
	int r = _logos_orig$_ungrouped$_LSServer_RebuildApplicationDatabases();

	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		
		
		const char *uicachePath = JBROOT_PATH_CSTRING("/usr/bin/uicache");
		if (!access(uicachePath, F_OK)) {
			exec_cmd(uicachePath, "-a", NULL);
		}
	});

	return r;
}

void lsdInit(void)
{
	MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
	if (coreServicesImage) {

		{void * _logos_symbol$_ungrouped$_LSGetInboxURLForBundleIdentifier = MSFindSymbol(coreServicesImage, "__LSGetInboxURLForBundleIdentifier"); MSHookFunction((void *)_logos_symbol$_ungrouped$_LSGetInboxURLForBundleIdentifier, (void *)&_logos_function$_ungrouped$_LSGetInboxURLForBundleIdentifier, (void **)&_logos_orig$_ungrouped$_LSGetInboxURLForBundleIdentifier);void * _logos_symbol$_ungrouped$_LSServer_RebuildApplicationDatabases = MSFindSymbol(coreServicesImage, "__LSServer_RebuildApplicationDatabases"); MSHookFunction((void *)_logos_symbol$_ungrouped$_LSServer_RebuildApplicationDatabases, (void *)&_logos_function$_ungrouped$_LSServer_RebuildApplicationDatabases, (void **)&_logos_orig$_ungrouped$_LSServer_RebuildApplicationDatabases);}
	}
}
