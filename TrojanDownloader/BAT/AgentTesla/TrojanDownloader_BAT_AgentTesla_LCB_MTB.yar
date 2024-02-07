
rule TrojanDownloader_BAT_AgentTesla_LCB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 00 63 00 65 00 64 00 62 00 38 00 62 00 66 00 2f 00 77 00 61 00 72 00 2f 00 77 00 65 00 69 00 76 00 2f 00 6c 00 70 00 2e 00 6e 00 69 00 62 00 65 00 74 00 73 00 61 00 70 00 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 } //01 00 
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00  GetObjectValue
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {43 6f 6e 74 61 69 6e 73 } //00 00  Contains
	condition:
		any of ($a_*)
 
}