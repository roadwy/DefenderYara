
rule Trojan_BAT_AgentTesla_CLP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CLP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 20 00 01 00 00 14 14 18 8d 90 01 03 01 25 16 06 11 04 18 d8 18 6f 90 01 03 0a a2 25 17 1f 10 8c 90 01 03 01 a2 6f 90 01 03 0a 28 90 01 03 0a 9c 11 04 17 d6 13 04 90 00 } //1
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //1 ArrayAttribute
		$a_01_4 = {50 61 72 61 6d 41 72 72 61 79 30 } //1 ParamArray0
		$a_01_5 = {53 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 53 } //1 S____________________________S
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}