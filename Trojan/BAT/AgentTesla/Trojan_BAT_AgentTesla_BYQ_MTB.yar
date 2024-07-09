
rule Trojan_BAT_AgentTesla_BYQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BYQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {04 02 50 7e ?? ?? ?? 04 91 7e ?? ?? ?? 04 61 d2 9c 38 ?? ?? ?? ?? 7e ?? ?? ?? 04 02 50 8e 69 } //1
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}