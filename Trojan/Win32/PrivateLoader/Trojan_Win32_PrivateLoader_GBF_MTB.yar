
rule Trojan_Win32_PrivateLoader_GBF_MTB{
	meta:
		description = "Trojan:Win32/PrivateLoader.GBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 d8 8b 14 04 8d b6 ?? ?? ?? ?? 0f b7 c3 89 16 86 c0 d3 f0 8b 07 66 3b df f5 81 c7 04 00 00 00 33 c3 e9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}