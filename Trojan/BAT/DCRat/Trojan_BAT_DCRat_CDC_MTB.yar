
rule Trojan_BAT_DCRat_CDC_MTB{
	meta:
		description = "Trojan:BAT/DCRat.CDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 07 00 00 0a 11 00 28 90 01 03 06 13 06 20 90 01 03 00 7e 90 01 03 04 7b 90 01 03 04 39 90 01 03 ff 26 20 90 01 03 00 38 90 01 03 ff 73 90 01 03 0a 13 02 20 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {49 6e 67 6a 71 67 76 66 6f 66 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  Ingjqgvfofy.Properties.Resources
	condition:
		any of ($a_*)
 
}