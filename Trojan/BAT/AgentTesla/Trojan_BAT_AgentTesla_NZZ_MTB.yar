
rule Trojan_BAT_AgentTesla_NZZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {20 20 20 50 69 40 73 2e 57 68 69 74 40 20 } //10    Pi@s.Whit@ 
		$a_01_1 = {54 6f 42 79 74 65 } //1 ToByte
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_81_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}
rule Trojan_BAT_AgentTesla_NZZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 00 0f 00 28 02 00 00 06 [0-09] d0 01 00 00 1b 28 14 00 00 0a 25 26 28 15 00 00 0a 25 26 a5 01 00 00 1b 0a 2b 00 06 2a } //1
		$a_03_1 = {11 00 0f 00 28 [0-13] d0 01 00 00 1b 28 ?? 00 00 0a 28 ?? 00 00 0a 25 26 a5 01 00 00 1b 0a 2b 00 06 2a } //1
		$a_01_2 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //10 GetDelegateForFunctionPointer
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*10) >=11
 
}