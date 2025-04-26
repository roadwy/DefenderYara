
rule Trojan_Win32_RedLineStealer_PB_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 d5 41 1d d4 8b ce f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 05 6b c0 ?? 2b c8 8a 81 ?? ?? ?? ?? 30 04 1e 46 3b f7 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLineStealer_PB_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 0f b6 92 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 0f b6 08 33 ca 8b 55 ?? 03 55 ?? 88 0a 8b 45 ?? 8b 08 83 c1 01 8b 55 ?? 89 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLineStealer_PB_MTB_3{
	meta:
		description = "Trojan:Win32/RedLineStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 05 89 45 0c 8b 45 ec 01 45 0c 8b 45 e8 83 25 ?? ?? ?? ?? ?? 03 c8 8d 04 3b 33 c8 31 4d 0c 8b 45 0c 01 05 44 7e b4 00 2b 75 0c } //1
		$a_03_1 = {8b 44 24 10 03 44 24 18 89 44 24 1c 8b 44 24 18 c1 e8 ?? 89 44 24 14 8b 44 24 14 33 74 24 1c 03 c3 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 14 75 68 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}