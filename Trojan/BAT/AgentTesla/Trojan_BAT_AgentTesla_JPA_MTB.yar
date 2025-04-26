
rule Trojan_BAT_AgentTesla_JPA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {0b 06 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 0d de 1e } //1
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {47 65 74 41 72 72 61 79 73 } //1 GetArrays
		$a_81_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_5 = {52 65 66 6c 65 63 74 69 6f 6e } //1 Reflection
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}