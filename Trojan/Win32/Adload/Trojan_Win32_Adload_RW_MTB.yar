
rule Trojan_Win32_Adload_RW_MTB{
	meta:
		description = "Trojan:Win32/Adload.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {5f 5f 43 50 50 64 65 62 75 67 48 6f 6f 6b } //1 __CPPdebugHook
		$a_81_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_2 = {53 79 73 74 65 6d 20 41 72 74 69 66 61 63 74 73 20 26 26 20 50 61 73 73 77 6f 72 64 73 } //1 System Artifacts && Passwords
		$a_81_3 = {50 61 73 73 77 6f 72 64 73 2f 4c 6f 67 69 6e 73 } //1 Passwords/Logins
		$a_81_4 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_81_5 = {53 63 72 65 65 6e 20 43 61 70 74 75 72 65 } //1 Screen Capture
		$a_81_6 = {44 65 74 65 63 74 20 42 69 74 6c 6f 63 6b 65 72 20 45 6e 63 72 79 70 74 69 6f 6e } //1 Detect Bitlocker Encryption
		$a_81_7 = {56 4d 20 43 50 55 20 43 6f 72 65 73 } //1 VM CPU Cores
		$a_81_8 = {56 4d 20 48 79 70 65 72 76 69 73 6f 72 } //1 VM Hypervisor
		$a_81_9 = {4b 69 6c 6c 54 69 6d 65 72 } //1 KillTimer
		$a_81_10 = {6b 4c 6f 61 64 65 72 4c 6f 63 6b } //1 kLoaderLock
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}