
rule Trojan_Win32_GuLoader_SIBU3_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBU3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {47 69 61 6e 74 44 6f 63 6b } //1 GiantDock
		$a_03_1 = {89 d3 c1 e2 ?? [0-05] 01 da 0f b6 1e 53 [0-0a] 01 da 81 f2 ?? ?? ?? ?? 83 c6 02 [0-0a] 66 8b 1e 66 83 fb 00 [0-0a] 75 } //1
		$a_03_2 = {38 06 8b 85 ?? ?? ?? ?? 73 ?? 89 c3 90 18 [0-05] c1 e0 ?? 01 d8 0f b6 0e 01 c8 35 ?? ?? ?? ?? 46 88 95 ?? ?? ?? ?? [0-05] 8a 16 [0-05] 80 fa 00 8a 95 90 1b 06 0f 85 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}