
rule TrojanSpy_Win32_Socelars_KA_MTB{
	meta:
		description = "TrojanSpy:Win32/Socelars.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0c 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 42 04 83 e8 70 8b 4d fc 8b 51 90 90 8b 4a 04 8b 55 fc 89 44 0a 8c 8b 4d fc 83 e9 60 e8 90 01 02 ff ff 8b 4d fc 83 e9 58 e8 90 00 } //05 00 
		$a_03_1 = {83 e8 70 8b 4d f0 8b 11 8b 4a 04 8b 55 f0 89 44 0a fc 6a 00 8b 4d f0 83 c1 10 e8 90 01 02 ff ff c6 45 fc 02 90 00 } //01 00 
		$a_00_2 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  http\shell\open\command
		$a_00_3 = {6e 67 64 61 74 61 73 2e 70 77 } //03 00  ngdatas.pw
		$a_00_4 = {69 70 63 6f 64 65 2e 70 77 } //03 00  ipcode.pw
		$a_00_5 = {6e 69 63 65 6b 6b 6b 2e 70 77 } //01 00  nicekkk.pw
		$a_00_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //01 00  ShellExecuteExW
		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //03 00  URLDownloadToFileW
		$a_00_8 = {63 68 61 6e 6e 65 6c 69 6e 66 6f 2e 70 77 2f 69 6e 64 65 78 2e 70 68 70 2f 48 6f 6d 65 2f 49 6e 64 65 78 2f 67 65 74 45 78 65 } //01 00  channelinfo.pw/index.php/Home/Index/getExe
		$a_00_9 = {46 3a 5c 66 61 63 65 62 6f 6f 6b 5f 73 76 6e 5c 74 72 75 6e 6b 5c 64 61 74 61 62 61 73 65 5c 52 65 6c 65 61 73 65 5c 73 65 61 72 7a 61 72 2e 70 64 62 } //01 00  F:\facebook_svn\trunk\database\Release\searzar.pdb
		$a_00_10 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 63 68 72 6f 6d 65 2e 65 78 65 } //01 00  cmd.exe /c taskkill /f /im chrome.exe
		$a_00_11 = {65 78 74 65 6e 73 69 6f 6e 73 2e 73 65 74 74 69 6e 67 73 2e 66 69 6b 6e 6e 6d 63 62 68 66 6d 63 68 69 64 68 6c 6d 6d 67 6f 6b 6c 6b 65 6f 67 6d 62 63 6d 64 } //00 00  extensions.settings.fiknnmcbhfmchidhlmmgoklkeogmbcmd
		$a_00_12 = {5d 04 00 00 a1 43 04 80 5c 39 00 00 a2 43 04 80 } //00 00 
	condition:
		any of ($a_*)
 
}