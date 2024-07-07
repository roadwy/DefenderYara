
rule Trojan_BAT_AgentTesla_EPN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 00 35 00 5a 00 38 00 34 00 35 00 53 00 35 00 41 00 48 00 44 00 41 00 45 00 35 00 48 00 47 00 47 00 4f 00 34 00 48 00 35 00 31 00 } //1 E5Z845S5AHDAE5HGGO4H51
		$a_01_1 = {43 00 61 00 72 00 6e 00 69 00 6c 00 61 00 } //1 Carnila
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}