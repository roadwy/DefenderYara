
rule Trojan_Win64_Grandoreiro_psyA_MTB{
	meta:
		description = "Trojan:Win64/Grandoreiro.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {75 02 eb 58 8a 06 3c 20 74 06 3c 09 74 02 eb 05 46 e2 f1 eb 47 c7 90 02 1f 8a 06 3c 46 76 02 24 df 2c 30 d7 a2 3a 47 40 00 b8 10 00 00 00 f7 25 36 47 40 00 a3 36 47 40 00 0f b6 05 3a 47 40 00 01 05 36 47 40 00 46 e2 d0 90 00 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}