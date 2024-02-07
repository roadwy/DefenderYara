
rule Trojan_BAT_AgentTesla_CQH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CQH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 4f 5f 30 5f 30 5f 30 5f 30 5f 30 5f 30 5f 30 5f 30 5f 30 5f 30 5f 30 00 } //01 00 
		$a_01_1 = {00 4f 5f 4f 5f 4f 5f 4f 5f 4f 5f 4f 5f 4f 5f 4f 5f 4f 5f 4f 00 } //01 00 
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_3 = {54 6f 42 79 74 65 } //01 00  ToByte
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {50 61 72 61 6d 58 47 72 6f 75 70 } //01 00  ParamXGroup
		$a_01_7 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_01_8 = {50 61 72 61 6d 58 41 72 72 61 79 } //00 00  ParamXArray
	condition:
		any of ($a_*)
 
}