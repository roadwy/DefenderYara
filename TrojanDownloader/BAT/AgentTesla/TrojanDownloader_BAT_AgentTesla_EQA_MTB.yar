
rule TrojanDownloader_BAT_AgentTesla_EQA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {34 00 35 00 2e 00 31 00 33 00 37 00 2e 00 32 00 32 00 2e 00 31 00 36 00 33 00 } //1 45.137.22.163
		$a_01_1 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_5 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //1 HttpWebResponse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}