
rule Trojan_Win64_LummaC_MGB_MTB{
	meta:
		description = "Trojan:Win64/LummaC.MGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 d0 44 89 d9 20 c1 44 30 d8 08 c8 89 c1 f6 d1 80 e1 d8 24 27 08 c8 89 c1 80 f1 27 34 c0 24 c1 89 cf 40 80 e7 3e 40 08 c7 41 89 f8 41 80 f0 3e 89 f0 34 9a 41 89 c3 41 20 f3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}