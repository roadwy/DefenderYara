
rule Trojan_BAT_AgentTesla_OU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {06 11 04 6f 90 02 04 06 18 6f 90 02 04 02 6f 90 02 04 16 02 6f 90 02 04 28 90 02 04 0c 28 90 02 04 06 6f 90 02 04 08 16 08 8e 69 6f 90 02 04 6f 90 02 04 0b 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_3 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}