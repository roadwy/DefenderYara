
rule Trojan_BAT_AgentTesla_JMG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 00 06 11 04 1f 10 28 ?? ?? ?? 0a d1 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 00 09 17 58 0d 09 08 8e 69 32 d5 } //1
		$a_81_1 = {53 70 6c 69 74 } //1 Split
		$a_81_2 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}