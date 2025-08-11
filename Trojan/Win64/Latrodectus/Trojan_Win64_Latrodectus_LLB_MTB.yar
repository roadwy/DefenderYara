
rule Trojan_Win64_Latrodectus_LLB_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.LLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {c5 f5 67 c9 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 44 30 14 0f c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 } //5
		$a_01_1 = {c5 e5 6a dc c5 f5 ef c9 48 ff c1 66 0f 70 fc 00 c5 fc 28 c1 c5 fc 28 d3 } //4
		$a_01_2 = {0f 28 dc 48 89 c8 0f 28 df 44 0f 14 c0 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=12
 
}