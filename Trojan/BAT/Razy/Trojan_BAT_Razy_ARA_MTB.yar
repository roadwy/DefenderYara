
rule Trojan_BAT_Razy_ARA_MTB{
	meta:
		description = "Trojan:BAT/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 10 11 04 07 08 9a 6f 90 01 03 0a 13 04 08 17 90 01 01 0c 08 11 05 31 eb 11 04 07 08 9a 90 00 } //01 00 
		$a_01_1 = {4c 00 61 00 6e 00 7a 00 61 00 64 00 6f 00 72 00 } //01 00 
		$a_01_2 = {50 00 61 00 69 00 6c 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Razy_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {18 18 73 23 00 00 0a 13 04 09 11 04 6f 90 01 03 0a de 0c 11 04 2c 07 11 04 6f 90 01 03 0a dc 02 7b 0b 00 00 04 28 90 00 } //01 00 
		$a_01_1 = {42 00 6c 00 61 00 63 00 6b 00 42 00 69 00 6e 00 64 00 65 00 72 00 53 00 74 00 75 00 62 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}