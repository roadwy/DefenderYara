
rule Trojan_BAT_Heracles_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 08 6f 90 01 01 00 00 0a 00 11 05 05 6f 90 01 01 00 00 0a 00 11 05 0e 04 6f 90 01 01 00 00 0a 00 11 05 6f 90 01 01 00 00 0a 0a 06 03 16 03 8e b7 6f 90 01 01 00 00 0a 13 04 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}