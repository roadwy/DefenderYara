
rule TrojanDownloader_BAT_AgentTesla_NCB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 90 02 02 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 90 00 } //1
		$a_01_1 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_80_2 = {44 78 6f 77 6e 78 6c 6f 78 61 64 44 78 61 74 78 78 61 78 } //DxownxloxadDxatxxax  1
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_5 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_6 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}