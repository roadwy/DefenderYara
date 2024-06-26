
rule TrojanDownloader_Win32_Agent_ACC{
	meta:
		description = "TrojanDownloader:Win32/Agent.ACC,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //0a 00  ShellExecuteA
		$a_01_2 = {6f 70 61 21 20 70 72 69 76 65 74 21 } //01 00  opa! privet!
		$a_01_3 = {68 74 74 70 3a 2f 2f 63 6f 75 6e 74 64 75 74 79 63 61 6c 6c 2e 69 6e 66 6f 2f 31 2f } //01 00  http://countdutycall.info/1/
		$a_03_4 = {2f 63 20 43 3a 5c 54 45 4d 50 5c 90 01 04 2e 62 61 74 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 90 00 } //01 00 
		$a_01_5 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 73 74 61 72 74 0d 0a 65 63 68 6f 20 3e 20 25 31 0d 0a 64 65 6c 20 25 31 0d 0a 69 66 20 65 78 69 73 74 20 25 31 20 67 6f 74 6f 20 73 74 61 72 74 0d 0a } //00 00 
	condition:
		any of ($a_*)
 
}