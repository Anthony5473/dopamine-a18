#line 1 "SpringBoard.x"
#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/objc.h>
#import <libroot.h>
#import <fcntl.h>

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

@interface XBSnapshotContainerIdentity : NSObject <NSCopying>
@property (nonatomic, readonly, copy) NSString* bundleIdentifier;
- (NSString*)snapshotContainerPath;
@end


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

@class XBSnapshotContainerIdentity; 
static NSString * (*_logos_orig$_ungrouped$XBSnapshotContainerIdentity$snapshotContainerPath)(_LOGOS_SELF_TYPE_NORMAL XBSnapshotContainerIdentity* _LOGOS_SELF_CONST, SEL); static NSString * _logos_method$_ungrouped$XBSnapshotContainerIdentity$snapshotContainerPath(_LOGOS_SELF_TYPE_NORMAL XBSnapshotContainerIdentity* _LOGOS_SELF_CONST, SEL); 

#line 28 "SpringBoard.x"



static NSString * _logos_method$_ungrouped$XBSnapshotContainerIdentity$snapshotContainerPath(_LOGOS_SELF_TYPE_NORMAL XBSnapshotContainerIdentity* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd) {
	NSString *path = _logos_orig$_ungrouped$XBSnapshotContainerIdentity$snapshotContainerPath(self, _cmd);
	if([path hasPrefix:@"/var/mobile/Library/SplashBoard/Snapshots/"] && ![self.bundleIdentifier hasPrefix:@"com.apple."]) {
		return JBROOT_PATH_NSSTRING(path);
	}
	return path;
}



__unused static int (*_logos_orig$_ungrouped$fcntl)(int fildes, int cmd, ...); __unused static int _logos_function$_ungrouped$fcntl(int fildes, int cmd, ...) {
	if (cmd == F_SETPROTECTIONCLASS) {
		char filePath[PATH_MAX];
		if (fcntl(fildes, F_GETPATH, filePath) != -1) {
			
			if (string_has_prefix(filePath, JBROOT_PATH_CSTRING("/var/mobile/Library/SplashBoard/Snapshots"))) {
				return 0;
			}
		}
	}

	va_list a;
	va_start(a, cmd);
	const char *arg1 = va_arg(a, void *);
	const void *arg2 = va_arg(a, void *);
	const void *arg3 = va_arg(a, void *);
	const void *arg4 = va_arg(a, void *);
	const void *arg5 = va_arg(a, void *);
	const void *arg6 = va_arg(a, void *);
	const void *arg7 = va_arg(a, void *);
	const void *arg8 = va_arg(a, void *);
	const void *arg9 = va_arg(a, void *);
	const void *arg10 = va_arg(a, void *);
	va_end(a);
	return _logos_orig$_ungrouped$fcntl(fildes, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

void springboardInit(void)
{
	{Class _logos_class$_ungrouped$XBSnapshotContainerIdentity = objc_getClass("XBSnapshotContainerIdentity"); { MSHookMessageEx(_logos_class$_ungrouped$XBSnapshotContainerIdentity, @selector(snapshotContainerPath), (IMP)&_logos_method$_ungrouped$XBSnapshotContainerIdentity$snapshotContainerPath, (IMP*)&_logos_orig$_ungrouped$XBSnapshotContainerIdentity$snapshotContainerPath);}void * _logos_symbol$_ungrouped$fcntl = (void *)fcntl; MSHookFunction((void *)_logos_symbol$_ungrouped$fcntl, (void *)&_logos_function$_ungrouped$fcntl, (void **)&_logos_orig$_ungrouped$fcntl);}
}
