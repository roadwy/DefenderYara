
rule Trojan_BAT_CryptInject_NVD_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {0d 06 08 6f ?? ?? ?? 0a 0b 07 16 73 ?? ?? ?? 0a 13 0b 11 0b 73 ?? ?? ?? 0a 13 04 7e } //1
		$a_01_1 = {57 1d b6 1d 09 09 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 01 01 00 00 74 00 00 00 cf 00 00 00 6b 02 00 00 62 00 00 00 a1 01 00 00 05 00 00 00 14 00 00 00 1c 00 00 00 01 00 00 00 01 00 00 00 02 } //1
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
		$a_01_4 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 } //1 CreateProcess
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_7 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 ZwUnmapViewOfSection
		$a_01_8 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}