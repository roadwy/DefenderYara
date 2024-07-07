
rule Trojan_BAT_AgentTesla_FN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {4c 61 6d 64 61 58 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 LamdaX.My.Resources
		$a_81_1 = {4c 61 6d 64 61 58 2e 48 79 61 74 74 2e 72 65 73 6f 75 72 63 65 73 } //1 LamdaX.Hyatt.resources
		$a_81_2 = {54 65 73 6c 61 } //1 Tesla
		$a_81_3 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_FN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 0a 00 00 "
		
	strings :
		$a_81_0 = {49 45 78 70 61 6e 64 6f 2e 50 6c 75 67 } //10 IExpando.Plug
		$a_81_1 = {78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 61 7a 78 } //10 硸硸硸硸硸硸硸硸硸愀硺
		$a_81_2 = {00 69 6d 69 6d 69 6d 69 6d 69 6d 00 } //10 椀業業業業m
		$a_81_3 = {4f 62 73 6f 6c 65 74 65 41 74 74 72 69 62 75 74 65 } //1 ObsoleteAttribute
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_81_6 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_8 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_00_9 = {4c 00 6f 00 61 00 64 00 00 0f 47 00 65 00 74 00 54 00 79 00 70 00 65 } //1
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_00_9  & 1)*1) >=36
 
}
rule Trojan_BAT_AgentTesla_FN_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0b 00 00 "
		
	strings :
		$a_81_0 = {24 37 62 38 34 64 33 64 38 2d 30 62 39 32 2d 34 39 61 35 2d 62 32 38 35 2d 33 38 35 35 61 65 61 62 65 39 62 34 } //20 $7b84d3d8-0b92-49a5-b285-3855aeabe9b4
		$a_81_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_2 = {46 6f 6c 64 7a 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Foldz.My.Resources
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=24
 
}