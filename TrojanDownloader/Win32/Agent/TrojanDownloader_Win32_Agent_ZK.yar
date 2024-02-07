
rule TrojanDownloader_Win32_Agent_ZK{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 65 36 50 61 74 63 68 42 61 72 2e 65 78 65 } //01 00  Ie6PatchBar.exe
		$a_00_1 = {4b 62 38 33 38 33 30 35 39 37 54 6d 70 4e 65 77 2e 65 78 65 } //01 00  Kb83830597TmpNew.exe
		$a_00_2 = {64 6f 77 6e 31 2e 65 78 65 } //01 00  down1.exe
		$a_00_3 = {4b 56 58 50 5f 4d 6f 6e 69 74 6f 72 } //01 00  KVXP_Monitor
		$a_00_4 = {43 75 73 74 6f 6d 5f 49 65 53 74 61 72 74 46 6c 61 67 } //01 00  Custom_IeStartFlag
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  Software\Microsoft\Internet Explorer\Main
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 65 74 75 70 5c 7b 32 35 30 44 38 46 42 41 2d 41 44 31 31 2d 31 31 44 30 32 33 2d 39 38 41 38 32 33 2d 30 38 30 30 32 34 32 33 31 30 32 7d } //01 00  Software\Microsoft\Windows\CurrentVersion\Setup\{250D8FBA-AD11-11D023-98A823-08002423102}
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
		$a_00_8 = {57 69 6e 64 6f 77 73 20 45 78 70 6c 6f 72 65 72 20 50 61 74 63 68 } //01 00  Windows Explorer Patch
		$a_00_9 = {41 70 70 45 76 65 6e 74 2e 65 78 65 } //01 00  AppEvent.exe
		$a_00_10 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}