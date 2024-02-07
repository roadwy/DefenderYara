
rule Trojan_BAT_Tedy_NYE_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 06 07 04 28 90 01 01 00 00 06 00 28 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 08 0d 90 00 } //01 00 
		$a_01_1 = {54 46 41 2e 44 61 74 61 2e 46 6f 72 6d 53 65 63 72 65 74 2e 72 65 73 6f 75 72 63 65 73 } //01 00  TFA.Data.FormSecret.resources
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}