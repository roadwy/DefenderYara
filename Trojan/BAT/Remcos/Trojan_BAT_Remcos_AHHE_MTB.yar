
rule Trojan_BAT_Remcos_AHHE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 15 07 11 08 06 11 08 9a 1f 10 28 90 01 03 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 90 00 } //01 00 
		$a_01_1 = {43 00 75 00 72 00 72 00 65 00 6e 00 63 00 79 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}