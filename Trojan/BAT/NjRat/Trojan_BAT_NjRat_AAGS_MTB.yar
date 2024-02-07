
rule Trojan_BAT_NjRat_AAGS_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AAGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {20 b9 d7 5b 0f 28 90 01 01 00 00 06 80 90 01 01 00 00 04 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 80 90 01 01 00 00 04 2a 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {7a 62 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  zbe.Resources.resources
	condition:
		any of ($a_*)
 
}