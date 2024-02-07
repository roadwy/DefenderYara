
rule Trojan_BAT_PureCrypt_NEAA_MTB{
	meta:
		description = "Trojan:BAT/PureCrypt.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 04 11 00 18 5b 11 02 11 00 18 28 90 01 01 00 00 06 1f 10 28 90 01 01 00 00 0a 9c 20 04 00 00 00 38 90 01 01 ff ff ff 11 00 11 07 3c 90 01 01 ff ff ff 38 90 01 01 ff ff ff 11 07 18 5b 90 00 } //02 00 
		$a_01_1 = {51 75 65 72 79 52 65 73 6f 6c 76 65 72 } //02 00  QueryResolver
		$a_01_2 = {4d 71 6f 67 68 65 74 6b } //00 00  Mqoghetk
	condition:
		any of ($a_*)
 
}