#!/bin/bash
# v35 syntax gate for the beacon instrumentation
set -u
cd /mnt/d/ios-buildenv/src/dopamine-a18 || exit 9
BB=BaseBin
INC="-I$BB/.include -IDopamine -I$BB/ChOma/include -IApplication/Dopamine/Exploits/Titan/exploit -IApplication/Dopamine/Exploits/ClearSword/exploit -I/mnt/d/ios-buildenv/_gateshims"
FLAGS=(-fsyntax-only -ObjC -DCPUFAMILY_ARM_COLL=0x0f0f0f0f -DCPUFAMILY_ARM_TAHITI=0x1a1a1a1a
       -target arm64-apple-ios15.0 -isysroot "$HOME/jbwork/sdks/iPhoneOS16.5.sdk")
rc=0
for f in \
  Application/Dopamine/Exploits/Titan/exploit/titan.m \
  Application/Dopamine/Exploits/Titan/exploit/gfx.m \
  Application/Dopamine/Exploits/Titan/exploit/a18_probe.c \
  Application/Dopamine/Exploits/Titan/exploit/ipc_port.c \
  Application/Dopamine/Exploits/Titan/exploit/kernel_patchfinder.c \
  Application/Dopamine/Exploits/ClearSword/exploit/krw.c \
  Application/Dopamine/Exploits/ClearSword/exploit/socket.c \
  Application/Dopamine/Exploits/ClearSword/exploit/poc.c \
  Application/Dopamine/Exploits/ClearSword/exploit/phys_oob.c \
  Application/Dopamine/Exploits/ClearSword/exploit/a18beacon.c \
  Application/Dopamine/Exploits/ClearSword/exploit/surface.c ; do
  echo "=== $f ==="
  clang "${FLAGS[@]}" $INC "$f" 2>&1 | grep -vE 'warning:|^\s*~|^\s*\^' | head -15
  if ! clang "${FLAGS[@]}" $INC "$f" >/dev/null 2>&1; then rc=1; echo "SYNTAX FAIL"; else echo "syntax OK"; fi
done
echo "=== gfx_patchfinder.c ==="
clang -fsyntax-only \
  -DCPUFAMILY_ARM_COLL=0x0f0f0f0f -DCPUFAMILY_ARM_TAHITI=0x1a1a1a1a \
  -target arm64-apple-ios15.0 -isysroot "$HOME/jbwork/sdks/iPhoneOS16.5.sdk" \
  $INC Application/Dopamine/Exploits/Titan/exploit/gfx_patchfinder.c 2>&1 | grep -vE 'warning:|^\s*~|^\s*\^' | head -15
if ! clang -fsyntax-only \
  -DCPUFAMILY_ARM_COLL=0x0f0f0f0f -DCPUFAMILY_ARM_TAHITI=0x1a1a1a1a \
  -target arm64-apple-ios15.0 -isysroot "$HOME/jbwork/sdks/iPhoneOS16.5.sdk" \
  $INC Application/Dopamine/Exploits/Titan/exploit/gfx_patchfinder.c >/dev/null 2>&1; then rc=1; echo "SYNTAX FAIL"; else echo "syntax OK"; fi
echo "OVERALL rc=$rc"
exit $rc
