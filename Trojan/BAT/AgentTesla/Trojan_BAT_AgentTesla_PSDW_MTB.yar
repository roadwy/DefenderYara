
rule Trojan_BAT_AgentTesla_PSDW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 cb 00 00 0a 13 04 11 04 17 6f cc 90 01 03 11 04 17 6f cd 90 01 03 11 04 0b 07 03 06 6f ce 90 01 03 0c 28 2a 90 01 03 08 02 16 02 8e 69 6f cf 90 01 03 6f 2b 90 01 03 0d 09 1f 10 6f d0 90 01 03 13 05 de 06 90 00 } //01 00 
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_2 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_01_3 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00  SymmetricAlgorithm
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}