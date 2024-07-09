
rule Trojan_BAT_CryptInject_PAV_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_03_0 = {fe 01 13 16 11 16 2c 10 19 45 01 00 00 00 f6 ff ff ff 73 1b 00 00 0a 7a 11 05 11 08 fe 01 13 17 11 17 2c 3a 18 45 01 00 00 00 f6 ff ff ff 00 09 7b 04 00 00 04 11 08 28 ?? ?? ?? 06 25 26 1f 64 28 ?? ?? ?? 06 fe 03 13 18 11 18 2c 10 1a 45 01 00 00 00 f6 ff ff ff } //1
		$a_01_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 } //1 CreateProcess
		$a_01_2 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 GetThreadContext
		$a_01_3 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64GetThreadContext
		$a_01_4 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_01_5 = {57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64SetThreadContext
		$a_01_6 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_8 = {55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 UnmapViewOfSection
		$a_01_9 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_10 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}