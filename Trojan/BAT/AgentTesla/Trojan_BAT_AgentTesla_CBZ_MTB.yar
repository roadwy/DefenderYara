
rule Trojan_BAT_AgentTesla_CBZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {00 70 72 6f 74 00 6b 69 63 6b 00 } //1
		$a_81_1 = {00 43 5f 44 00 70 32 00 69 32 00 } //1
		$a_81_2 = {00 48 75 6e 74 65 72 00 53 00 } //1 䠀湵整rS
		$a_81_3 = {00 52 65 74 75 72 6e 45 72 72 6f 72 00 4d 65 73 73 61 67 65 00 } //1
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_6 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_81_7 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_8 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_9 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_10 = {50 61 72 61 6d 41 72 72 61 79 30 } //1 ParamArray0
		$a_81_11 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //1 ArrayAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}