
rule Trojan_BAT_Formbook_NEAG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NEAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {25 16 1f 2d 9d 6f 75 00 00 0a 0b 07 8e 69 8d b4 00 00 01 0c 16 13 05 2b 16 08 11 05 07 11 05 9a 1f 10 28 76 00 00 0a d2 9c 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dd } //05 00 
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}