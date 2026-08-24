#line 1 "cfprefsd.x"
#import <Foundation/Foundation.h>
#import <substrate.h>

BOOL preferencePlistNeedsRedirection(NSString *plistPath)
{
	if ([plistPath hasPrefix:@"/private/var/mobile/Containers"] || [plistPath hasPrefix:@"/var/db"] || [plistPath hasPrefix:@"/var/jb"]) return NO;

	NSString *plistName = plistPath.lastPathComponent;

	if ([plistName hasPrefix:@"com.apple."] || [plistName hasPrefix:@"systemgroup.com.apple."] || [plistName hasPrefix:@"group.com.apple."]) return NO;

	NSArray *additionalSystemPlistNames = @[
		@".GlobalPreferences.plist",
		@".GlobalPreferences_m.plist",
		@"bluetoothaudiod.plist",
		@"NetworkInterfaces.plist",
		@"OSThermalStatus.plist",
		@"preferences.plist",
		@"osanalyticshelper.plist",
		@"UserEventAgent.plist",
		@"wifid.plist",
		@"dprivacyd.plist",
		@"silhouette.plist",
		@"nfcd.plist",
		@"kNPProgressTrackerDomain.plist",
		@"siriknowledged.plist",
		@"UITextInputContextIdentifiers.plist",
		@"mobile_storage_proxy.plist",
		@"splashboardd.plist",
		@"mobile_installation_proxy.plist",
		@"languageassetd.plist",
		@"ptpcamerad.plist",
		@"com.google.gmp.measurement.monitor.plist",
		@"com.google.gmp.measurement.plist",
	];

	return ![additionalSystemPlistNames containsObject:plistName];
}


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




#line 40 "cfprefsd.x"
__unused static BOOL (*_logos_orig$_ungrouped$_CFPrefsGetPathForTriplet)(CFStringRef bundleIdentifier, CFStringRef user, BOOL byHost, CFStringRef path, UInt8 *buffer); __unused static BOOL _logos_function$_ungrouped$_CFPrefsGetPathForTriplet(CFStringRef bundleIdentifier, CFStringRef user, BOOL byHost, CFStringRef path, UInt8 *buffer)
{
	BOOL orig = _logos_orig$_ungrouped$_CFPrefsGetPathForTriplet(bundleIdentifier, user, byHost, path, buffer);

	if(orig && buffer && !access("/var/jb", F_OK))
	{
		NSString* origPath = [NSString stringWithUTF8String:(char*)buffer];
		BOOL needsRedirection = preferencePlistNeedsRedirection(origPath);
		if (needsRedirection) {
			
			strcpy((char*)buffer, "/var/jb");
			strcat((char*)buffer, origPath.UTF8String);
		}
	}

	return orig;
}

void cfprefsdInit(void)
{
	MSImageRef coreFoundationImage = MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
	if (coreFoundationImage) {
		{void * _logos_symbol$_ungrouped$_CFPrefsGetPathForTriplet = MSFindSymbol(coreFoundationImage, "__CFPrefsGetPathForTriplet"); MSHookFunction((void *)_logos_symbol$_ungrouped$_CFPrefsGetPathForTriplet, (void *)&_logos_function$_ungrouped$_CFPrefsGetPathForTriplet, (void **)&_logos_orig$_ungrouped$_CFPrefsGetPathForTriplet);}
	}
}
