
rule Trojan_BAT_nJRat_ANJ_MTB{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 64 11 64 16 11 62 a2 00 11 64 17 07 11 61 17 28 90 01 01 00 00 0a a2 00 11 64 18 11 0c 11 61 17 28 90 01 01 00 00 0a a2 00 11 64 19 11 17 11 61 17 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_nJRat_ANJ_MTB_2{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0d 2b 41 7e 07 00 00 04 11 04 6f 90 01 03 0a 74 03 00 00 01 6f 90 01 03 0a 2c 25 11 04 08 fe 01 16 fe 01 2c 17 7e 07 00 00 04 08 7e 07 00 00 04 11 04 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_nJRat_ANJ_MTB_3{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {1f 09 8d 1e 00 00 01 13 0d 11 0d 16 11 04 a2 00 11 0d 17 11 05 08 17 28 90 01 03 0a a2 00 11 0d 18 11 06 08 17 28 90 01 03 0a a2 00 11 0d 19 11 07 08 17 28 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_nJRat_ANJ_MTB_4{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 18 00 00 0a 0a 06 28 19 00 00 0a 03 6f 1a 00 00 0a 6f 1b 00 00 0a 0b 73 1c 00 00 0a 0c 08 07 6f 1d 00 00 0a 00 08 18 6f 1e 00 00 0a 00 08 6f 1f 00 00 0a 02 16 02 8e 69 6f 20 00 00 0a 0d 09 13 04 2b 00 11 04 } //01 00 
		$a_01_1 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  TripleDESCryptoServiceProvider
	condition:
		any of ($a_*)
 
}