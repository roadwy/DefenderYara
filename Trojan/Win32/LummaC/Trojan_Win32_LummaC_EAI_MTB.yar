
rule Trojan_Win32_LummaC_EAI_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c6 c1 e8 05 89 45 f8 8b 45 e4 01 45 f8 8b 4d f0 c1 e6 04 03 75 d8 8d 14 0b 33 f2 81 3d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}