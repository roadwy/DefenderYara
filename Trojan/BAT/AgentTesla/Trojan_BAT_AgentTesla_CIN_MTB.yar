
rule Trojan_BAT_AgentTesla_CIN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 57 53 53 00 54 00 58 58 58 58 58 58 00 } //1 圀卓吀堀塘塘X
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //1 ArrayAttribute
		$a_01_3 = {50 61 72 61 6d 41 72 72 61 79 30 } //1 ParamArray0
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}