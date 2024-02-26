
rule Trojan_BAT_Marsilia_AMBG_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {9e 06 06 08 94 06 09 94 58 20 00 01 00 00 5d 94 13 90 01 01 11 90 01 01 11 90 01 01 03 11 90 01 01 91 11 90 01 01 61 28 90 01 04 9c 00 11 90 01 01 17 58 13 90 01 01 11 90 01 01 03 8e 69 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}