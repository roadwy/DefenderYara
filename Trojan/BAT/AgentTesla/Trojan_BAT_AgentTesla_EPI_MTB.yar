
rule Trojan_BAT_AgentTesla_EPI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 00 cc 06 59 00 46 06 86 06 } //01 00 
		$a_01_1 = {67 65 74 5f 48 65 6c 70 65 72 5f 43 6c 61 73 73 65 73 } //01 00  get_Helper_Classes
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_4 = {48 61 73 65 6e 64 61 } //01 00  Hasenda
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_7 = {43 6f 6d 70 75 74 65 48 61 73 68 } //00 00  ComputeHash
	condition:
		any of ($a_*)
 
}