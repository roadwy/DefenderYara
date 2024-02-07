
rule Trojan_BAT_AgentTesla_NQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 43 61 70 74 49 74 } //01 00  get_CaptIt
		$a_81_1 = {44 61 74 61 49 4e 73 65 72 74 } //01 00  DataINsert
		$a_81_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_81_3 = {49 6e 73 65 72 74 50 69 63 74 75 72 65 } //01 00  InsertPicture
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_81_6 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_81_7 = {67 65 74 5f 42 69 67 45 6e 64 69 61 6e 55 6e 69 63 6f 64 65 } //01 00  get_BigEndianUnicode
		$a_81_8 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}