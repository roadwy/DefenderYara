
rule Trojan_BAT_AgentTesla_OS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {08 8e 69 6f 90 02 04 6f 90 09 35 00 28 90 02 04 03 6f 90 02 04 6f 90 02 09 6f 90 02 04 06 18 6f 90 02 04 02 28 90 02 04 0c 28 90 02 04 06 6f 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_81_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}