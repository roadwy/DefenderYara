
rule Trojan_BAT_AgentTesla_EQJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {34 00 41 00 37 00 46 00 43 00 47 00 38 00 44 00 37 00 54 00 4a 00 5a 00 44 00 34 00 59 00 35 00 41 00 53 00 30 00 42 00 37 00 47 00 } //10 4A7FCG8D7TJZD4Y5AS0B7G
		$a_01_1 = {53 00 74 00 72 00 75 00 63 00 74 00 } //5 Struct
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}