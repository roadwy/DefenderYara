
rule TrojanDownloader_BAT_AgentTesla_ABI_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 df a3 1d 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 bb 00 00 00 f2 00 00 00 f9 01 00 00 00 04 00 00 eb 02 00 00 } //5
		$a_01_1 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_01_4 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_5 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //1 get_IsAttached
		$a_01_6 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_7 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //1 GetAllNetworkInterfaces
		$a_01_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=13
 
}
rule TrojanDownloader_BAT_AgentTesla_ABI_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 28 26 90 01 02 0a 13 07 28 27 90 01 02 0a 11 07 6f 28 90 01 02 0a 13 08 7e 29 90 01 02 0a 26 08 28 26 90 01 02 0a 13 09 28 27 90 01 02 0a 11 09 6f 28 90 01 02 0a 13 0a 07 28 26 90 01 02 0a 13 0b 28 27 90 01 02 0a 11 0b 6f 28 90 01 02 0a 13 0c 73 24 90 01 02 0a 11 0c 28 2a 90 01 02 0a 13 0d 06 11 0a 6f 2a 90 01 02 0a 13 0e 19 8d 01 90 01 02 01 13 11 11 11 16 90 00 } //6
		$a_01_1 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //1 GetEnumerator
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}