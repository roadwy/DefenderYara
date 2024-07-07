
rule TrojanDownloader_BAT_AgentTesla_ABO_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {09 2c 07 09 6f 1a 90 01 02 0a 00 dc 08 6f 1b 90 01 02 0a 13 04 de 16 90 0a 49 00 00 72 01 90 01 02 70 28 04 90 01 02 06 0a 06 73 15 90 01 02 0a 0b 00 73 16 90 01 02 0a 0c 00 07 16 73 17 90 01 02 0a 73 18 90 01 02 0a 0d 00 09 08 6f 19 90 01 02 0a 00 00 de 0b 90 00 } //5
		$a_01_1 = {42 75 66 66 65 72 65 64 53 74 72 65 61 6d } //1 BufferedStream
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}
rule TrojanDownloader_BAT_AgentTesla_ABO_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {0d 09 2c 68 00 06 72 90 01 03 70 08 72 74 90 01 02 70 28 90 01 03 0a 6f 90 01 03 0a 00 08 72 a0 90 01 02 70 28 90 01 03 0a 28 90 01 03 0a 00 08 72 74 90 01 02 70 28 90 01 03 0a 08 28 90 01 03 0a 00 1f 0a 90 00 } //4
		$a_01_1 = {5a 69 70 46 69 6c 65 } //1 ZipFile
		$a_01_2 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_3 = {45 78 74 72 61 63 74 54 6f 44 69 72 65 63 74 6f 72 79 } //1 ExtractToDirectory
		$a_01_4 = {52 00 6f 00 62 00 6c 00 6f 00 78 00 50 00 6c 00 61 00 79 00 65 00 72 00 42 00 65 00 74 00 61 00 2e 00 7a 00 69 00 70 00 } //1 RobloxPlayerBeta.zip
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}