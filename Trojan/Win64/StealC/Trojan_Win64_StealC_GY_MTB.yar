
rule Trojan_Win64_StealC_GY_MTB{
	meta:
		description = "Trojan:Win64/StealC.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 d1 44 30 c1 20 ca 30 d1 08 d1 44 30 c1 44 30 c0 89 c2 30 ca 20 c8 } //3
		$a_01_1 = {30 c8 20 d1 44 08 c2 44 30 e2 08 c2 89 d0 44 30 e0 44 20 c3 08 cb 89 c1 20 d1 } //1
		$a_01_2 = {30 d8 20 d3 08 d9 20 d0 89 c2 20 ca 30 c8 08 d0 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}