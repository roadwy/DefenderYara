
rule Trojan_BAT_Remcos_AHTI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0d 09 08 6f 90 01 03 0a 00 09 18 6f 90 01 03 0a 00 09 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 13 04 11 04 17 28 90 00 } //01 00 
		$a_01_1 = {4c 00 6f 00 4c 00 4e 00 6f 00 74 00 65 00 73 00 } //01 00  LoLNotes
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}