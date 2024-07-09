
rule Trojan_BAT_AgentTesla_JPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a dd ?? ?? ?? 00 08 39 ?? ?? ?? 00 08 6f } //1
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
		$a_81_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}