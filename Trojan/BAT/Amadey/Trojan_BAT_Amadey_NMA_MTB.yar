
rule Trojan_BAT_Amadey_NMA_MTB{
	meta:
		description = "Trojan:BAT/Amadey.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {12 02 02 8e 69 17 59 28 90 01 01 00 00 2b 00 08 13 07 20 90 01 01 00 00 00 38 90 01 01 00 00 00 00 28 90 01 01 00 00 0a 03 28 90 01 01 00 00 06 0a 20 90 01 01 00 00 00 38 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_1 = {47 65 6f 6d 65 74 72 69 5f 4f 64 65 76 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  Geometri_Odev.Properties
	condition:
		any of ($a_*)
 
}