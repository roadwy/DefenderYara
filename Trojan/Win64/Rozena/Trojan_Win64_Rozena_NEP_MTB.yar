
rule Trojan_Win64_Rozena_NEP_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 73 a4 00 00 f2 44 0f 11 44 24 90 01 01 49 89 d8 48 8d 15 7a 14 0b 00 f2 0f 11 7c 24 90 01 01 48 89 c1 49 90 00 } //3
		$a_03_1 = {e8 c2 a6 09 00 4c 8d 05 90 01 04 48 8d 15 44 62 0a 00 48 89 c1 48 8d 05 90 01 04 48 89 01 e8 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}