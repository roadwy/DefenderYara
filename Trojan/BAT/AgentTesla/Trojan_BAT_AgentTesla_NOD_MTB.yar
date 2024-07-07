
rule Trojan_BAT_AgentTesla_NOD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 35 66 38 66 31 33 38 34 2d 33 33 63 64 2d 34 62 37 30 2d 61 39 63 31 2d 31 63 61 34 62 64 65 62 63 32 31 66 } //1 $5f8f1384-33cd-4b70-a9c1-1ca4bdebc21f
		$a_01_1 = {48 43 56 51 75 65 73 74 69 6f 6e 6e 61 69 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 HCVQuestionnaire.Properties.Resources.resources
		$a_01_2 = {49 44 65 66 65 72 72 65 64 } //1 IDeferred
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}