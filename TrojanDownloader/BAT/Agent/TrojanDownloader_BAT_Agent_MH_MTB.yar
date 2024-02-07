
rule TrojanDownloader_BAT_Agent_MH_MTB{
	meta:
		description = "TrojanDownloader:BAT/Agent.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 72 6b 74 6b 73 73 6b 61 73 66 64 } //01 00  srktksskasfd
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_6 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_7 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_9 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_10 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_11 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}