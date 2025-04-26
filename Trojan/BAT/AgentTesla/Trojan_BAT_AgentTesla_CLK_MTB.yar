
rule Trojan_BAT_AgentTesla_CLK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 07 11 05 18 d8 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 05 17 d6 13 05 } //1
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //1 ArrayAttribute
		$a_01_4 = {50 61 72 61 6d 41 72 72 61 79 30 } //1 ParamArray0
		$a_01_5 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}