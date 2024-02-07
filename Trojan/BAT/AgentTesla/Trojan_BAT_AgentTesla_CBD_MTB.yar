
rule Trojan_BAT_AgentTesla_CBD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {09 11 04 6f 90 01 03 0a 13 05 07 11 05 08 da 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 00 11 04 17 d6 13 04 11 04 09 6f 90 01 03 0a fe 04 13 06 11 06 2d ca 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CBD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {00 53 00 50 72 6f 54 00 } //01 00  匀倀潲T
		$a_81_1 = {00 48 75 6e 74 65 72 00 } //01 00  䠀湵整r
		$a_81_2 = {00 43 61 6c 6c 73 74 61 63 6b 00 4b 69 63 6b 00 } //01 00  䌀污獬慴正䬀捩k
		$a_81_3 = {00 63 6f 6c 6f 72 00 52 65 74 75 72 6e 45 72 72 6f 72 00 } //01 00 
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_6 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_7 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_8 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_9 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_81_10 = {50 61 72 61 6d 41 72 72 61 79 30 } //01 00  ParamArray0
		$a_81_11 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //00 00  ArrayAttribute
	condition:
		any of ($a_*)
 
}