
rule TrojanDownloader_BAT_AgentTesla_N_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 31 34 38 30 39 35 39 65 2d 35 62 66 31 2d 34 32 31 35 2d 62 32 31 65 2d 63 61 37 38 63 66 30 61 66 32 36 36 } //1 $1480959e-5bf1-4215-b21e-ca78cf0af266
		$a_01_1 = {43 75 62 69 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Cubin.Properties.Resources.resources
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_7 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}