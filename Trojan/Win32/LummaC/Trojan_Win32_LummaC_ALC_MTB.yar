
rule Trojan_Win32_LummaC_ALC_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d7 81 e7 00 b7 67 da 89 d3 81 f3 00 b7 67 5a 21 f2 8d 3c 7b 01 f7 01 d2 29 d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaC_ALC_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.ALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 50 6a 4b 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 50 6a 4b 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}