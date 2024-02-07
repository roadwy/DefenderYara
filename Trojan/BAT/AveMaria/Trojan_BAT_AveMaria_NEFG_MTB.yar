
rule Trojan_BAT_AveMaria_NEFG_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 32 00 16 0c 2b 19 00 03 07 08 6f 90 01 01 00 00 0a 0d 06 07 12 03 28 90 01 01 00 00 0a 9c 00 08 17 58 0c 08 03 6f 90 01 01 00 00 0a fe 04 13 04 11 04 2d d8 00 07 17 58 0b 07 03 6f 90 01 01 00 00 0a fe 04 13 05 11 05 2d bf 06 13 06 2b 00 11 06 90 00 } //02 00 
		$a_01_1 = {44 75 6e 67 65 6f 6e 47 61 6d 65 } //00 00  DungeonGame
	condition:
		any of ($a_*)
 
}