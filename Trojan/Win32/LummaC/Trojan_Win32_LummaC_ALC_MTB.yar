
rule Trojan_Win32_LummaC_ALC_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d7 81 e7 00 b7 67 da 89 d3 81 f3 00 b7 67 5a 21 f2 8d 3c 7b 01 f7 01 d2 29 d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}