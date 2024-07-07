
rule Trojan_BAT_AgentTesla_NOL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 66 65 63 38 65 66 62 33 2d 64 35 35 64 2d 34 31 30 34 2d 62 39 66 30 2d 30 61 65 62 62 66 33 34 31 33 33 61 } //1 $fec8efb3-d55d-4104-b9f0-0aebbf34133a
		$a_01_1 = {50 79 72 69 74 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Pyrite.Properties.Resources.resources
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}