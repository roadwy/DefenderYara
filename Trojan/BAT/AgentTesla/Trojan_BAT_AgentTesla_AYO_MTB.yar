
rule Trojan_BAT_AgentTesla_AYO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {5a 42 4a 55 43 45 35 37 5a 45 37 41 46 34 4a 5a } //01 00  ZBJUCE57ZE7AF4JZ
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_81_6 = {66 6c 6f 72 61 } //01 00  flora
		$a_81_7 = {53 6d 61 72 74 45 78 74 65 6e 73 69 6f 6e 73 } //01 00  SmartExtensions
		$a_81_8 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_81_9 = {41 45 53 5f 44 65 63 72 79 70 74 } //00 00  AES_Decrypt
	condition:
		any of ($a_*)
 
}