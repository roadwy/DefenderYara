
rule Trojan_BAT_Heracles_ABQR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ABQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 00 06 18 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 0b 7e 90 01 01 00 00 04 02 07 6f 90 01 01 00 00 06 0c 2b 00 08 2a 90 0a 3f 00 28 90 01 01 00 00 0a 0a 06 7e 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}