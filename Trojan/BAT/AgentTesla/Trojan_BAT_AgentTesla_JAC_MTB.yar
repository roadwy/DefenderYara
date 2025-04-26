
rule Trojan_BAT_AgentTesla_JAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0a 00 00 "
		
	strings :
		$a_00_0 = {8a 00 42 5f d8 a8 00 6b 00 58 58 00 58 58 58 00 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 } //10
		$a_00_1 = {a1 d8 a1 d8 a1 d8 a1 d8 a1 d8 a1 d8 a1 d8 a1 00 78 00 50 6f 69 6e 74 00 70 31 00 d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 } //10
		$a_00_2 = {b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 00 53 00 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 } //10
		$a_00_3 = {ab d8 ab d8 ab d8 ab 00 d8 a1 d8 a1 d8 a1 d8 a1 d8 } //10
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_6 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_81_7 = {50 61 72 61 6d 41 72 72 61 79 30 } //1 ParamArray0
		$a_81_8 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //1 ArrayAttribute
		$a_81_9 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //1 NewLateBinding
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=46
 
}