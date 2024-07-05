
rule Trojan_BAT_Amadey_NA_MTB{
	meta:
		description = "Trojan:BAT/Amadey.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 13 00 00 0a 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 25 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 18 00 00 0a 90 00 } //01 00 
		$a_01_1 = {56 65 6e 6f 6d 6f 75 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  Venomous.Properties.Resources
	condition:
		any of ($a_*)
 
}