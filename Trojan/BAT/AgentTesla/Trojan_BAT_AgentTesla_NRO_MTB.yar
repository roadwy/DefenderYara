
rule Trojan_BAT_AgentTesla_NRO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 1f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 05 01 00 00 17 00 00 00 03 02 00 00 08 0e 00 00 6e 04 00 00 05 03 00 00 e2 09 00 00 bf 00 00 00 13 } //1
		$a_01_1 = {39 30 30 2d 34 31 32 38 2d 34 34 63 30 2d 39 39 34 } //1 900-4128-44c0-994
		$a_01_2 = {52 65 63 6f 70 69 65 72 42 6f 78 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 RecopierBox.Resources.resource
		$a_01_3 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}