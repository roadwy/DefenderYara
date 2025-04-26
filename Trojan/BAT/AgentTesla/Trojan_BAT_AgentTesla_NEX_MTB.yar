
rule Trojan_BAT_AgentTesla_NEX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 09 00 00 "
		
	strings :
		$a_01_0 = {44 33 33 33 42 41 41 43 2d 30 37 34 33 2d 34 46 36 31 2d 39 43 39 43 2d 33 36 38 43 34 32 36 34 42 44 37 35 } //10 D333BAAC-0743-4F61-9C9C-368C4264BD75
		$a_01_1 = {53 70 61 6e 20 54 61 67 20 52 65 6d 6f 76 65 72 } //10 Span Tag Remover
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=25
 
}