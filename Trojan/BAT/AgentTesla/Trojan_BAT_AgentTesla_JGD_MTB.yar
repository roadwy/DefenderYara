
rule Trojan_BAT_AgentTesla_JGD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0a 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 d0 ?? ?? ?? 1b 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a 14 17 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 a2 6f ?? ?? ?? 0a 74 ?? ?? ?? 01 7d ?? ?? ?? 04 7e ?? ?? ?? 04 2d 24 16 d0 ?? ?? ?? 01 28 ?? ?? ?? 0a } //10
		$a_81_1 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_81_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_6 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_7 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_8 = {55 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //1 UnaryOperation
		$a_81_9 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=19
 
}