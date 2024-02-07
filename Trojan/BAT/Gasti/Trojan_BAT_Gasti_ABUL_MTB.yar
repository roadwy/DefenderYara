
rule Trojan_BAT_Gasti_ABUL_MTB{
	meta:
		description = "Trojan:BAT/Gasti.ABUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 2d 06 09 28 90 01 01 00 00 06 5a 28 90 01 01 00 00 0a 6e 7e 90 01 01 00 00 04 8e 69 6a 5d 13 04 07 7e 90 01 01 00 00 04 11 04 d4 93 6f 90 01 01 00 00 0a 26 09 17 58 0d 09 02 32 cf 07 6f 90 01 01 00 00 0a 2a 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}