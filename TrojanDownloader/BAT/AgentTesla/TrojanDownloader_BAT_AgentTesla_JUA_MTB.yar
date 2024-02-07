
rule TrojanDownloader_BAT_AgentTesla_JUA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.JUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 0a 00 "
		
	strings :
		$a_81_0 = {54 65 73 74 2d 4e 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 20 2d 54 72 61 63 65 52 6f 75 74 65 } //01 00  Test-NetConnection -TraceRoute
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 73 74 6f 72 65 32 2e 67 6f 66 69 6c 65 2e 69 6f 2f 64 6f 77 6e 6c 6f 61 64 2f } //01 00  https://store2.gofile.io/download/
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_81_5 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_6 = {62 69 6e 67 } //01 00  bing
		$a_81_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_8 = {44 65 62 75 67 20 4d 6f 64 65 21 } //00 00  Debug Mode!
	condition:
		any of ($a_*)
 
}