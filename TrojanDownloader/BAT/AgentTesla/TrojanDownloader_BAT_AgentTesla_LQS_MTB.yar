
rule TrojanDownloader_BAT_AgentTesla_LQS_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 62 75 79 73 72 69 6c 61 6e 6b 61 6e 2e 6c 6b 2f 70 70 2f 43 6f 6e 73 6f 6c 65 41 70 70 } //01 00  https://buysrilankan.lk/pp/ConsoleApp
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_3 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}