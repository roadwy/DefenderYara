
rule Trojan_Win32_Zenpak_G_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 4d ec 8a 14 01 8b 45 e8 8b 4d f0 88 14 01 8b 45 e8 05 01 00 00 00 89 45 e8 eb c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_G_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 e8 0f b6 3c 06 01 d7 89 45 ?? 31 d2 8b 5d f0 f7 f3 8b 75 ec 0f b6 14 16 01 d7 89 f8 99 f7 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_G_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 02 2b 4d ?? 8b 75 ?? 88 1c 06 01 c8 8b 4d ?? 39 c8 89 45 ?? 74 ?? 90 13 8b 45 ?? b9 ?? ?? ?? ?? 8b 55 } //1
		$a_02_1 = {88 1c 06 83 c0 ?? c6 45 f1 ?? 8b 7d ?? 39 f8 89 45 [0-10] 90 13 8b 45 [0-10] 8b 55 ?? 8a 1c 02 [0-10] 8b 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}