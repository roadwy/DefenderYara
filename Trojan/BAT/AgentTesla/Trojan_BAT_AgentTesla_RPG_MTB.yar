
rule Trojan_BAT_AgentTesla_RPG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {62 00 6d 00 6e 00 2e 00 6c 00 70 00 6d 00 70 00 62 00 61 00 6e 00 74 00 65 00 6e 00 2e 00 69 00 64 00 [0-40] 2e 00 70 00 6e 00 67 00 } //1
		$a_01_1 = {4b 61 73 70 65 72 73 6b 79 } //1 Kaspersky
		$a_01_2 = {41 6e 74 69 2d 56 69 72 75 73 } //1 Anti-Virus
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_4 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_5 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_6 = {53 74 72 69 6e 67 } //1 String
		$a_01_7 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}