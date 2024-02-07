
rule TrojanDownloader_BAT_AgentTesla_LIN_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 37 39 2e 34 33 2e 31 38 37 2e 31 33 31 2f 75 65 79 74 2f } //01 00  http://179.43.187.131/ueyt/
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //00 00  WebClient
	condition:
		any of ($a_*)
 
}