
rule Trojan_BAT_DarkKomet_AALJ_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.AALJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 0d 16 13 04 2b 2a 09 11 04 9a 13 05 07 72 90 01 02 00 70 11 05 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 26 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 06 11 06 2d c9 90 00 } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}