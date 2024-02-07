
rule Trojan_BAT_Stealerc_AAPW_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AAPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 08 11 03 6f 90 01 01 00 00 0a 20 00 00 00 00 28 90 01 01 00 00 06 3a 90 01 01 ff ff ff 26 38 90 01 01 ff ff ff 00 11 08 17 28 90 01 01 00 00 06 38 90 01 01 ff ff ff 00 00 11 08 6f 90 01 01 00 00 0a 13 06 20 01 00 00 00 28 90 01 01 00 00 06 3a 90 01 01 ff ff ff 26 38 90 01 01 ff ff ff 00 11 06 11 09 16 11 09 8e 69 6f 90 01 01 00 00 0a 13 0c 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}