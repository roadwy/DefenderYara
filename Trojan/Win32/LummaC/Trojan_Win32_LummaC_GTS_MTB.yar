
rule Trojan_Win32_LummaC_GTS_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 83 c0 ?? 89 04 24 ?? 83 2c 24 ?? 8a 04 24 30 04 32 42 3b d7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_LummaC_GTS_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 04 ?? ?? ?? ?? 31 c1 89 ca f7 d2 83 e2 ?? 81 e1 ?? ?? ?? ?? 29 d1 88 8c 04 ?? ?? ?? ?? 40 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}