
rule Trojan_BAT_AgentTesla_NST_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 5d a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 73 00 00 00 13 00 00 00 23 00 00 00 0f 01 00 00 32 00 00 00 c0 00 00 00 01 00 00 00 7d 00 00 00 01 00 00 00 25 00 00 00 0a 00 00 00 17 } //1
		$a_01_1 = {35 64 39 31 31 65 30 30 65 61 66 31 } //1 5d911e00eaf1
		$a_01_2 = {62 38 33 32 38 32 39 37 } //1 b8328297
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}