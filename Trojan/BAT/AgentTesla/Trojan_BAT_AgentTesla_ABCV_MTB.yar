
rule Trojan_BAT_AgentTesla_ABCV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 09 16 09 8e 69 6f 90 01 03 0a de 0b 15 2c 07 11 04 6f 90 01 03 0a dc 07 6f 90 01 03 0a 13 07 de 38 90 0a 32 00 07 06 6f 90 01 03 0a 17 73 90 00 } //01 00 
		$a_01_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00  SymmetricAlgorithm
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}