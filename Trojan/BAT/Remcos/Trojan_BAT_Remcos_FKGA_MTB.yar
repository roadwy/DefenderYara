
rule Trojan_BAT_Remcos_FKGA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FKGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 05 08 09 11 04 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c8 90 00 } //01 00 
		$a_01_1 = {42 00 61 00 74 00 74 00 6c 00 65 00 73 00 68 00 69 00 70 00 4c 00 69 00 74 00 65 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 } //00 00  BattleshipLiteLibrary
	condition:
		any of ($a_*)
 
}