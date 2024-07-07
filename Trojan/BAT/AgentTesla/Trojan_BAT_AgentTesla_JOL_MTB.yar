
rule Trojan_BAT_AgentTesla_JOL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 34 36 32 39 64 38 62 32 2d 62 31 36 32 2d 34 34 61 39 2d 61 32 30 37 2d 66 32 62 30 62 34 32 32 33 34 63 35 } //1 $4629d8b2-b162-44a9-a207-f2b0b42234c5
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_81_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}