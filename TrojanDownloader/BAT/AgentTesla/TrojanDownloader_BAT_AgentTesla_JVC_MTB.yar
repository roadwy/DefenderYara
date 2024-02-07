
rule TrojanDownloader_BAT_AgentTesla_JVC_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.JVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 73 74 6f 72 65 32 2e 67 6f 66 69 6c 65 2e 69 6f 2f 64 6f 77 6e 6c 6f 61 64 2f } //01 00  https://store2.gofile.io/download/
		$a_81_1 = {44 00 65 00 62 00 75 00 67 00 00 09 4d 00 6f 00 64 00 65 } //01 00 
		$a_81_2 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_81_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}