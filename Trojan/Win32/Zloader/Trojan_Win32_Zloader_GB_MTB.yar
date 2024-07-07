
rule Trojan_Win32_Zloader_GB_MTB{
	meta:
		description = "Trojan:Win32/Zloader.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 32 88 0c 38 8b 55 f8 83 c2 01 89 55 f8 eb 90 01 01 a1 90 01 04 a3 90 01 04 5f 5e 8b e5 5d c3 90 0a 32 00 03 45 fc 8b 55 f4 90 00 } //10
		$a_02_1 = {03 01 8b 55 08 89 02 8b 45 08 8b 08 83 e9 01 8b 55 08 89 0a 8b e5 5d c3 90 0a 28 00 8b 55 90 01 01 8d 44 02 90 01 01 8b 4d 08 90 00 } //10
		$a_02_2 = {89 11 5d c3 90 0a 41 00 81 c2 90 01 04 a1 90 01 04 8b ca a3 90 01 04 8b 15 90 01 04 31 90 01 05 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 8b 15 90 00 } //10
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}