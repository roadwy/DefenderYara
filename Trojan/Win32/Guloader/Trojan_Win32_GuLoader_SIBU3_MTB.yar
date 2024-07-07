
rule Trojan_Win32_GuLoader_SIBU3_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBU3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {47 69 61 6e 74 44 6f 63 6b } //1 GiantDock
		$a_03_1 = {89 d3 c1 e2 90 01 01 90 02 05 01 da 0f b6 1e 53 90 02 0a 01 da 81 f2 90 01 04 83 c6 02 90 02 0a 66 8b 1e 66 83 fb 00 90 02 0a 75 90 00 } //1
		$a_03_2 = {38 06 8b 85 90 01 04 73 90 01 01 89 c3 90 18 90 02 05 c1 e0 90 01 01 01 d8 0f b6 0e 01 c8 35 90 01 04 46 88 95 90 01 04 90 02 05 8a 16 90 02 05 80 fa 00 8a 95 90 1b 06 0f 85 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}