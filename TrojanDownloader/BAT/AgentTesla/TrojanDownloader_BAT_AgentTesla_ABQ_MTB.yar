
rule TrojanDownloader_BAT_AgentTesla_ABQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 16 11 04 6f ?? ?? ?? 0a 08 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 25 13 04 16 30 e2 09 6f ?? ?? ?? 0a 0a de 1e } //5
		$a_03_1 = {0a 19 6f 17 ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 d0 ?? ?? ?? 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 8d ?? ?? ?? 01 25 16 02 a2 6f ?? ?? ?? 06 de 03 90 0a 3f 00 72 31 ?? ?? 70 28 16 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule TrojanDownloader_BAT_AgentTesla_ABQ_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 df a3 1d 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 b7 00 00 00 f0 00 00 00 f9 01 00 00 fd 03 00 00 eb 02 00 00 } //5
		$a_01_1 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_2 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //1 HttpWebResponse
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_5 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //1 get_IsAttached
		$a_01_6 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_7 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //1 GetAllNetworkInterfaces
		$a_01_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=13
 
}