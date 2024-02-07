
rule Trojan_BAT_Lokibot_DC_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 04 00 00 14 00 "
		
	strings :
		$a_03_0 = {25 16 03 a2 14 14 28 90 01 03 0a 74 90 01 03 01 0c 08 14 02 72 90 01 03 70 28 90 01 03 06 28 90 01 03 0a 17 8d 90 01 03 01 25 16 02 72 90 01 03 70 28 90 01 03 06 a2 14 14 90 00 } //01 00 
		$a_81_1 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //01 00  ISectionEntry
		$a_81_2 = {53 74 72 52 65 76 65 72 73 65 78 } //01 00  StrReversex
		$a_81_3 = {65 70 79 54 74 65 47 } //00 00  epyTteG
	condition:
		any of ($a_*)
 
}