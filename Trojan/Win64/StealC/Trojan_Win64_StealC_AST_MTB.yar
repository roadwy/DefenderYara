
rule Trojan_Win64_StealC_AST_MTB{
	meta:
		description = "Trojan:Win64/StealC.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 c1 e4 38 49 c1 e7 30 4d 09 e7 49 c1 e6 28 48 c1 e3 20 48 c1 e7 18 49 c1 e3 10 49 c1 e1 08 4d 09 d1 4d 09 d9 49 09 f9 49 09 d9 4d 09 f1 4d 09 f9 4e 33 0c 00 4e 89 4c 05 f0 45 31 c9 49 89 d0 } //1
		$a_01_1 = {44 0f b6 44 0a 02 41 c1 e0 10 44 0f b7 0c 0a 45 01 c8 41 81 c0 00 00 00 cb 44 33 04 10 44 89 44 15 f0 48 83 c2 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}