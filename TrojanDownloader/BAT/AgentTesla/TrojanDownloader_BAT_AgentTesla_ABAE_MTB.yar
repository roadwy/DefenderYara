
rule TrojanDownloader_BAT_AgentTesla_ABAE_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 11 33 94 b4 6f ?? ?? ?? 0a 00 11 33 17 d6 13 33 11 33 11 32 31 e6 11 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 16 13 08 11 07 } //1
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {53 00 47 00 42 00 49 00 54 00 50 00 6c 00 61 00 63 00 65 00 6d 00 65 00 6e 00 74 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 SGBITPlacementManagementSystem.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}