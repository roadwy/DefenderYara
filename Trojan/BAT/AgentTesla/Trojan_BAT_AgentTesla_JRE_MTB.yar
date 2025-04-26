
rule Trojan_BAT_AgentTesla_JRE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {fe 0e 04 00 38 38 00 00 00 fe 0d 04 00 28 16 00 00 0a fe 0e 05 00 fe 0c 05 00 28 17 00 00 0a fe 0c 02 00 28 18 00 00 0a da fe 0e 06 00 fe 0c 03 00 fe 0c 06 00 28 19 00 00 0a 6f 1a 00 00 0a 26 00 fe 0d 04 } //1
		$a_81_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_81_2 = {43 6f 6e 76 65 72 74 46 72 6f 6d 55 74 66 33 32 } //1 ConvertFromUtf32
		$a_81_3 = {43 6f 6e 66 65 72 65 6e 63 65 52 65 67 69 73 74 72 61 74 69 6f 6e 2e 4d 79 } //1 ConferenceRegistration.My
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}