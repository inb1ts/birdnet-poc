# birdnet-poc
Experimental PoC for unhooking API functions using in-memory patching, without VirtualProtect, for one specific EDR.

Accompanying blog post: https://inbits-sec.com/posts/in-memory-unhooking/


### Brief Overview

The PoC covers an approach to unhooking Crowdstrike Falcon hooks in NTDLL. It does this by finding the relocated syscall stub, and then finding a specific heap location through in-memory disassembly in order to patch a jump and bypass the hook.

