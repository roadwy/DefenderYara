
rule Trojan_BAT_Nanocore_NA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {62 60 0c 28 90 01 03 0a 7e 90 01 03 04 02 08 6f 90 01 03 0a 28 90 01 03 0a a5 90 01 03 1b 0b 11 07 20 e2 90 00 } //01 00 
		$a_01_1 = {43 69 6e 65 6d 61 4d 61 6e 61 67 65 6d 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  CinemaManagement.Properties.Resources.resources
	condition:
		any of ($a_*)
 
}