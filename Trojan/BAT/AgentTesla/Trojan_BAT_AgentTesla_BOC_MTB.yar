
rule Trojan_BAT_AgentTesla_BOC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 0b 00 00 "
		
	strings :
		$a_81_0 = {50 65 78 65 73 6f 43 6f 72 65 00 43 6f 72 65 } //10
		$a_81_1 = {50 65 78 65 73 6f 43 6c 61 73 73 } //10 PexesoClass
		$a_81_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_81_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_5 = {55 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //1 UnaryOperation
		$a_81_6 = {42 69 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //1 BinaryOperation
		$a_81_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_10 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=29
 
}