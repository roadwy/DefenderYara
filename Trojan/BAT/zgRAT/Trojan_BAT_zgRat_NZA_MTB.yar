
rule Trojan_BAT_zgRat_NZA_MTB{
	meta:
		description = "Trojan:BAT/zgRat.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 0f 00 00 0a 28 90 01 03 06 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 0a dd 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 32 32 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  WindowsFormsApp22.Properties
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_zgRat_NZA_MTB_2{
	meta:
		description = "Trojan:BAT/zgRat.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 0c 00 00 06 0a 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 75 90 01 01 00 00 1b 0b 07 16 07 8e 69 28 10 00 00 0a 07 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 35 37 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  WindowsFormsApp57.Properties.Resources.resources
	condition:
		any of ($a_*)
 
}