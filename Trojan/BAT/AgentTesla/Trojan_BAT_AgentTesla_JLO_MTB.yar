
rule Trojan_BAT_AgentTesla_JLO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 14 14 18 8d ?? ?? ?? 01 25 16 08 06 18 d8 18 6f ?? ?? ?? 0a a2 25 17 1f 10 8c ?? ?? ?? 01 a2 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 9c 06 17 d6 0a 06 11 04 31 } //1
		$a_81_1 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_81_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}