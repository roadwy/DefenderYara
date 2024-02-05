
rule Trojan_BAT_Seraph_AAKS_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f 90 01 01 01 00 0a 06 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 13 04 73 90 01 01 00 00 0a 0c 08 11 04 17 73 90 01 01 01 00 0a 0d 09 07 16 07 8e 69 6f 90 01 01 01 00 0a 08 6f 90 01 01 01 00 0a 13 05 de 1e 09 6f 90 01 01 00 00 0a dc 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}