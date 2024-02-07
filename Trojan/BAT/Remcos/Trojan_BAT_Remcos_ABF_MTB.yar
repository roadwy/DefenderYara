
rule Trojan_BAT_Remcos_ABF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 16 06 8e 69 6f 90 01 03 0a 13 04 11 04 03 28 90 01 03 06 28 90 01 03 06 72 90 01 03 70 6f 90 01 03 0a 80 90 01 03 04 02 03 73 90 01 03 0a 8c 90 01 03 01 13 05 2b 00 11 05 2a 90 00 } //01 00 
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}