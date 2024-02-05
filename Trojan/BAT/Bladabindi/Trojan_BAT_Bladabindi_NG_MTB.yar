
rule Trojan_BAT_Bladabindi_NG_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 09 11 09 16 72 90 01 04 a2 00 11 09 16 6f 90 01 04 13 07 11 07 16 9a 72 90 01 04 28 90 01 04 0c 11 07 8e b7 19 2e 06 11 07 17 9a 2b 0e 11 07 17 9a 72 90 01 04 28 90 01 04 10 01 06 11 04 28 90 01 04 04 6f 90 02 15 0a 00 06 08 28 90 01 08 0a 00 06 17 90 00 } //01 00 
		$a_01_1 = {15 a2 09 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 7b 00 00 00 10 00 00 00 35 00 00 00 86 00 00 00 44 00 00 00 d1 } //00 00 
	condition:
		any of ($a_*)
 
}