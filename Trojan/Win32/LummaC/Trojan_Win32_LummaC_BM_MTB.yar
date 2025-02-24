
rule Trojan_Win32_LummaC_BM_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 8b 0d ?? ?? ?? 00 81 c1 fa 00 00 00 8b 55 f8 0f b6 02 33 c1 8b 4d f8 88 01 e9 } //4
		$a_01_1 = {03 c2 33 d2 b9 00 01 00 00 f7 f1 89 15 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}