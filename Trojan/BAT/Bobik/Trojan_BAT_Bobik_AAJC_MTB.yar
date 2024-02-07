
rule Trojan_BAT_Bobik_AAJC_MTB{
	meta:
		description = "Trojan:BAT/Bobik.AAJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 0b 03 28 90 01 01 00 00 0a 0c 73 90 01 01 00 00 0a 0d 08 73 90 01 01 00 00 0a 13 04 11 04 09 06 07 6f 90 01 01 00 00 0a 16 73 90 01 01 00 00 0a 13 05 11 05 73 90 01 01 00 00 0a 13 06 11 06 6f 90 01 01 00 00 0a 13 07 de 0a 26 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {57 00 46 00 5f 00 44 00 6f 00 63 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  WF_Doc.Properties.Resources
	condition:
		any of ($a_*)
 
}