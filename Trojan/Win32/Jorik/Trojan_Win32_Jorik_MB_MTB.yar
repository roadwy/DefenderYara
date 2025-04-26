
rule Trojan_Win32_Jorik_MB_MTB{
	meta:
		description = "Trojan:Win32/Jorik.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 85 74 fd ff ff 03 05 ?? ?? ?? ?? 8b 08 03 0d ?? ?? ?? ?? 8b 95 74 fd ff ff 03 15 ?? ?? ?? ?? 89 0a a1 ?? ?? ?? ?? 83 c0 71 8b 8d 74 fd ff ff 03 0d ?? ?? ?? ?? 33 01 8b 95 74 fd ff ff 03 15 ?? ?? ?? ?? 89 02 eb } //1
		$a_01_1 = {8b 55 08 03 55 f8 8a 45 f4 88 02 eb } //1
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_3 = {2e 69 63 6d 5c 50 65 72 73 69 73 74 65 6e 74 48 61 6e 64 6c 65 72 } //1 .icm\PersistentHandler
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}