
rule Trojan_BAT_Spynoon_AAFF_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 02 05 04 8e 69 6f 90 01 01 00 00 0a 0a 06 0b 2b 00 07 2a 90 0a 1b 00 7e 90 01 01 00 00 04 6f 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {4d 00 61 00 69 00 6e 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 } //00 00  Main_Project
	condition:
		any of ($a_*)
 
}