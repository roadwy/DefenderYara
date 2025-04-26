
rule Trojan_Win32_LummaC_AMCS_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 14 24 89 c1 e8 ?? ?? ?? ?? 83 ec 04 0f b6 00 32 45 e0 88 45 f7 } //4
		$a_03_1 = {89 14 24 89 c1 e8 ?? ?? ?? ?? 83 ec 04 0f b6 5d 9c 88 18 83 45 e4 01 8b 45 e4 3b 45 10 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}