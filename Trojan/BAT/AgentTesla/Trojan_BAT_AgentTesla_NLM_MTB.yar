
rule Trojan_BAT_AgentTesla_NLM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {24 34 63 35 33 39 31 35 61 2d 31 66 30 35 2d 34 65 35 63 2d 38 64 63 66 2d 32 66 34 65 32 32 39 31 62 33 62 34 } //1 $4c53915a-1f05-4e5c-8dcf-2f4e2291b3b4
		$a_01_1 = {43 43 2e 43 6f 6d 6d 6f 6e 2e 55 74 69 6c 73 } //1 CC.Common.Utils
		$a_01_2 = {42 6f 61 72 64 45 78 61 6d 70 6c 65 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 BoardExample.Form1.resources
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {45 76 65 6e 74 4c 69 73 74 65 6e 65 72 } //1 EventListener
		$a_01_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_10 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_11 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}