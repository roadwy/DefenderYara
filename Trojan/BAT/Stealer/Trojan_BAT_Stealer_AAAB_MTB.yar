
rule Trojan_BAT_Stealer_AAAB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AAAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 18 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a a5 90 01 01 00 00 01 6f 90 01 01 00 00 0a 00 08 18 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a a5 90 01 01 00 00 01 6f 90 01 01 00 00 0a 00 08 72 28 0c 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 08 6f 90 01 01 00 00 0a 0d 09 07 16 07 8e 69 6f 90 01 01 00 00 0a 13 04 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}