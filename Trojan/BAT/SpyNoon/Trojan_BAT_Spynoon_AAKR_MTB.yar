
rule Trojan_BAT_Spynoon_AAKR_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 06 03 1f 10 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 6f 90 01 01 00 00 0a 06 18 6f 90 01 01 00 00 0a 06 06 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 02 07 28 90 01 01 00 00 06 10 00 02 0c de 0a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}