
rule Trojan_BAT_Crysan_EAS_MTB{
	meta:
		description = "Trojan:BAT/Crysan.EAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {02 11 01 28 90 01 01 00 00 06 13 02 20 00 00 00 00 7e 90 01 01 01 00 04 7b 90 01 01 01 00 04 39 90 01 01 ff ff ff 26 20 00 00 00 00 38 90 01 01 ff ff ff 28 90 01 01 00 00 0a 11 03 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 01 38 90 00 } //02 00 
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 34 00 37 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  WindowsFormsApp47.Properties.Resources
	condition:
		any of ($a_*)
 
}