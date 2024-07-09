
rule Trojan_BAT_AgentTesla_BBO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {0a 08 18 2c [0-01] 17 58 0c 08 07 8e 69 32 [0-01] 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 2a 73 ?? ?? ?? 0a ?? ?? ?? ?? ?? 0a ?? ?? ?? ?? ?? 6f ?? ?? ?? 0a 2b } //10
		$a_81_1 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_81_2 = {53 74 61 72 74 54 65 73 74 73 } //1 StartTests
		$a_81_3 = {52 65 66 52 65 67 4d 6f 64 65 6c } //1 RefRegModel
		$a_81_4 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}