
rule Trojan_BAT_Spynoon_AAKY_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 08 11 08 28 90 01 01 00 00 06 11 08 28 90 01 01 00 00 06 28 90 01 01 00 00 06 13 0b 20 00 00 00 00 7e 90 01 01 01 00 04 7b 90 01 01 01 00 04 3a 90 01 01 ff ff ff 26 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //00 00  ReadAsByteArrayAsync
	condition:
		any of ($a_*)
 
}