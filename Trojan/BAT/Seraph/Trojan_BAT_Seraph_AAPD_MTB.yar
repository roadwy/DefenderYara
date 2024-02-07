
rule Trojan_BAT_Seraph_AAPD_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 13 04 73 90 01 01 02 00 0a 0b 02 28 90 01 01 05 00 06 75 90 01 01 00 00 1b 73 90 01 01 02 00 0a 0c 08 11 04 16 73 90 01 01 02 00 0a 0d 09 07 6f 90 01 01 02 00 0a 07 13 05 de 15 09 6f 90 01 01 00 00 0a dc 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}