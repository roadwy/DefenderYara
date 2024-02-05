
rule Trojan_BAT_Bladabindi_NEO_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 1d 00 00 0a 72 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 28 1d 00 00 0a 72 90 01 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 90 00 } //01 00 
		$a_01_1 = {4a 00 61 00 77 00 72 00 48 00 4a 00 66 00 57 00 66 00 } //01 00 
		$a_01_2 = {4c 4f 53 54 2e 44 49 52 } //00 00 
	condition:
		any of ($a_*)
 
}