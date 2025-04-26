
rule Trojan_Win32_LummaC_EAT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 c1 31 d1 89 4d f0 8b 4d f0 80 c1 32 88 8c 06 b6 da 2b d9 40 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}