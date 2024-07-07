
rule Trojan_BAT_AgentTesla_JGG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_00_0 = {6a 69 69 0c 02 4f 05 64 63 62 61 9f b5 eb 1d b7 7b 78 58 73 76 26 75 74 71 70 71 8f a3 f9 0d 47 6b 6a 69 d2 47 64 65 64 43 62 61 9f d5 e9 1d 57 7b 3a 79 78 57 76 75 74 71 72 71 8b a5 fb 0d 47 6b 6a 69 6e 67 66 65 64 63 62 61 9f 35 e9 1d 57 79 7a 79 78 77 76 75 77 73 12 f4 8f a5 eb 0d 47 7b 6a 69 68 67 76 65 64 73 62 61 9f 35 6b } //10
		$a_80_1 = {44 65 6c 61 79 } //Delay  1
		$a_80_2 = {54 6f 53 74 72 69 6e 67 } //ToString  1
		$a_80_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //DebuggerBrowsableState  1
		$a_80_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //DebuggerNonUserCodeAttribute  1
		$a_80_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggableAttribute  1
		$a_80_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggerBrowsableAttribute  1
		$a_80_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //DebuggerHiddenAttribute  1
		$a_80_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //DebuggingModes  1
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=18
 
}