
rule Trojan_BAT_AgentTesla_IN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {57 ff a2 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 0d 01 00 00 af 02 00 00 c8 05 00 00 90 01 01 0d 00 00 90 01 01 07 00 00 7b 00 00 00 90 01 01 03 00 00 10 00 00 00 90 00 } //01 00 
		$a_01_1 = {53 00 68 00 61 00 72 00 70 00 52 00 70 00 63 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  SharpRpc.Properties.Resources
		$a_81_2 = {52 75 6e 20 4f 6e 63 65 20 57 72 61 70 70 65 72 } //01 00  Run Once Wrapper
		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_IN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.IN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 01 00 "
		
	strings :
		$a_81_0 = {00 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 00 } //01 00 
		$a_81_1 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_6 = {47 65 74 46 69 6c 65 4e 61 6d 65 42 79 55 52 4c } //01 00  GetFileNameByURL
		$a_81_7 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //01 00  Create__Instance__
		$a_81_8 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //01 00  DeflateStream
		$a_81_9 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 61 7a 78 00 } //01 00  砀硸硸硸硸硸硸硸硸x穡x
		$a_81_10 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_11 = {4c 6f 61 64 00 73 61 64 } //01 00  潌摡猀摡
		$a_81_12 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_13 = {69 6d 69 6d 69 6d 69 6d 69 6d } //01 00  imimimimim
		$a_81_14 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_15 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}