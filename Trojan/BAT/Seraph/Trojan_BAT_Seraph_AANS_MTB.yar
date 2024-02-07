
rule Trojan_BAT_Seraph_AANS_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AANS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 13 07 14 0b 2b 0c 00 28 90 01 01 00 00 06 0b de 03 26 de 00 07 2c f1 73 90 01 01 00 00 0a 0c 07 73 90 01 01 00 00 0a 13 04 11 04 11 07 16 73 90 01 01 00 00 0a 13 05 11 05 08 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 0a de 1e 11 05 6f 90 01 01 00 00 0a dc 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}