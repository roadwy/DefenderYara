
rule Trojan_BAT_Scarsi_ABIP_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.ABIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {09 11 05 09 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 09 17 6f 90 01 03 0a 06 13 06 08 09 6f 90 01 03 0a 17 73 90 01 03 0a 13 07 11 07 11 06 16 11 06 8e 69 6f 90 01 03 0a de 0c 11 07 2c 07 11 07 6f 90 01 03 0a dc 08 6f 90 01 03 0a 13 08 de 14 90 00 } //01 00 
		$a_01_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00  SymmetricAlgorithm
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}