
rule Trojan_BAT_Crysan_AAHW_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 28 90 01 01 00 00 0a 04 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0d 07 09 6f 90 01 01 00 00 0a 00 07 18 6f 90 01 01 00 00 0a 00 07 6f 90 01 01 00 00 0a 03 16 03 8e 69 6f 90 01 01 00 00 0a 0a 2b 00 06 2a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}