
rule TrojanDownloader_BAT_AgentTesla_JZR_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.JZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 2d 00 73 00 20 00 35 00 } //01 00  Start-Sleep -s 5
		$a_01_1 = {57 61 69 74 46 6f 72 45 78 69 74 } //01 00  WaitForExit
		$a_81_2 = {54 65 73 74 } //01 00  Test
		$a_01_3 = {53 68 6f 77 57 69 6e 64 6f 77 } //01 00  ShowWindow
		$a_81_4 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_6 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_01_7 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_8 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //01 00  GetCurrentProcess
		$a_01_9 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}