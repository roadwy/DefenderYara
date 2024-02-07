
rule Trojan_BAT_DCRat_DA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {18 2d 26 26 28 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 72 90 01 01 00 00 70 7e 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 1d 2d 06 26 de 13 0b 2b d8 0c 2b f8 26 de 00 06 17 58 0a 06 1b 32 c0 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}