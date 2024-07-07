
rule Trojan_BAT_AgentTesla_AO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 17 02 0a 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 6b 00 00 00 27 00 00 00 } //1
		$a_01_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}