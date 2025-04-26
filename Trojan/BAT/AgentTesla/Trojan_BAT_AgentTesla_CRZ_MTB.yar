
rule Trojan_BAT_AgentTesla_CRZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {00 58 30 46 54 5f 46 54 32 00 53 00 } //1 堀䘰彔呆2S
		$a_03_1 = {58 30 46 54 5f 46 54 31 [0-15] 4d 65 73 73 61 67 65 } //1
		$a_01_2 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_3 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_6 = {50 61 72 61 6d 58 47 72 6f 75 70 } //1 ParamXGroup
		$a_01_7 = {50 61 72 61 6d 58 41 72 72 61 79 } //1 ParamXArray
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}