#line 1 "main.x"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>

NSString* safe_getExecutablePath()
{
	char executablePathC[PATH_MAX];
	uint32_t executablePathCSize = sizeof(executablePathC);
	_NSGetExecutablePath(&executablePathC[0], &executablePathCSize);
	return [NSString stringWithUTF8String:executablePathC];
}

NSString* getProcessName()
{
	return safe_getExecutablePath().lastPathComponent;
}

static __attribute__((constructor)) void _logosLocalCtor_b89687fa(int __unused argc, char __unused **argv, char __unused **envp)
{
	NSString *processName = getProcessName();
	



if ([processName isEqualToString:@"cfprefsd"]) {
		extern void cfprefsdInit(void);
		cfprefsdInit();
	}
	else if ([processName isEqualToString:@"SpringBoard"]) {
		extern void springboardInit(void);
		springboardInit();
	}
	else if ([processName isEqualToString:@"lsd"]) {
		extern void lsdInit(void);
		lsdInit();
	}
}
