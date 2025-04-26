
rule Trojan_Win64_Rozena_EM_MTB{
	meta:
		description = "Trojan:Win64/Rozena.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 03 00 00 00 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 80 } //3
		$a_01_1 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 02 00 00 01 ba 00 00 00 00 48 89 c1 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}