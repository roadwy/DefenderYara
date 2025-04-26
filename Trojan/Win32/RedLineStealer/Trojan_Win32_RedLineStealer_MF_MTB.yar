
rule Trojan_Win32_RedLineStealer_MF_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 ?? ?? ?? ?? 88 0c 02 c9 c2 } //1
		$a_03_1 = {8b 45 08 33 45 0c 81 45 f8 ?? ?? ?? ?? 33 c1 2b f0 ff 4d f0 0f 85 } //1
		$a_01_2 = {4f 70 65 6e 4d 75 74 65 78 57 } //1 OpenMutexW
		$a_01_3 = {56 69 72 74 75 61 6c 4c 6f 63 6b } //1 VirtualLock
		$a_01_4 = {43 72 65 61 74 65 4d 61 69 6c 73 6c 6f 74 41 } //1 CreateMailslotA
		$a_01_5 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 45 78 41 } //1 GetDiskFreeSpaceExA
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}