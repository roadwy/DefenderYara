
rule Trojan_BAT_Blackshades_AEY_MTB{
	meta:
		description = "Trojan:BAT/Blackshades.AEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 03 d6 17 d6 8d 28 00 00 01 28 90 01 03 0a 74 09 00 00 1b 0a 02 06 08 03 6f 90 01 03 0a 0d 09 16 2e 06 08 09 d6 0c 2b d1 90 00 } //01 00 
		$a_01_1 = {67 65 74 53 74 72 65 61 6d 42 79 74 65 73 58 } //01 00 
		$a_01_2 = {67 00 61 00 67 00 61 00 65 00 68 00 67 00 68 00 66 00 78 00 68 00 66 00 78 00 } //01 00 
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_4 = {61 00 6e 00 61 00 67 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}