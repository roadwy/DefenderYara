
rule Trojan_BAT_LummaC_KAC_MTB{
	meta:
		description = "Trojan:BAT/LummaC.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 ff 54 75 e3 6f c7 8e 1d a2 72 e5 ca d9 4e fe 8c 18 30 60 80 6e 15 30 4f d6 1c } //4
		$a_01_1 = {90 e8 15 80 de 6a c9 ef 9c 39 73 44 81 02 05 3c 09 00 a2 73 e7 ce e2 f4 e9 } //3
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}