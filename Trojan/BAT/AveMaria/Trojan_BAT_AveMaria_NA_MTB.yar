
rule Trojan_BAT_AveMaria_NA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 08 00 00 0a 6f 90 01 01 00 00 0a 14 17 8d 90 01 01 00 00 01 25 16 07 a2 6f 90 01 01 00 00 0a 75 90 01 01 00 00 1b 08 28 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 2a 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 34 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  WindowsFormsApp40.Properties.Resources.resources
	condition:
		any of ($a_*)
 
}