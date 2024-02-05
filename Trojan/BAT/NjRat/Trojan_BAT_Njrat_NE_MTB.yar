
rule Trojan_BAT_Njrat_NE_MTB{
	meta:
		description = "Trojan:BAT/Njrat.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 95 58 20 90 01 01 00 00 00 5f 95 61 28 90 01 01 00 00 06 9c 00 11 08 17 58 13 08 11 08 11 05 8e 69 fe 04 13 09 11 09 2d 9b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}