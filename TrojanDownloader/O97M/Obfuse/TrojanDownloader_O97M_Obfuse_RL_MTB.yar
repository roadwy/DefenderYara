
rule TrojanDownloader_O97M_Obfuse_RL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 49 73 45 6d 70 74 79 28 22 22 29 } //01 00  = IsEmpty("")
		$a_01_1 = {3d 20 49 73 4e 75 6d 65 72 69 63 28 22 22 29 } //01 00  = IsNumeric("")
		$a_03_2 = {2e 49 74 65 6d 28 29 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 90 02 15 2c 90 00 } //01 00 
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 22 90 02 10 22 2c 20 22 90 02 10 22 2c 20 22 26 22 29 20 5f 90 00 } //01 00 
		$a_03_4 = {3d 20 52 65 70 6c 61 63 65 28 22 90 02 06 22 2c 20 22 90 02 06 22 2c 20 22 48 22 29 90 00 } //01 00 
		$a_03_5 = {26 20 52 65 70 6c 61 63 65 28 22 90 02 06 22 2c 20 22 90 02 06 22 2c 20 22 22 29 90 00 } //01 00 
		$a_01_6 = {26 20 22 34 } //01 00  & "4
		$a_01_7 = {26 20 22 33 } //01 00  & "3
		$a_01_8 = {26 20 22 32 } //00 00  & "2
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_RL_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 7a 2e 66 69 2f 65 76 69 6c 31 2f 6c 61 75 6e 63 68 65 72 2e 70 73 31 22 90 0a 2e 00 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 90 00 } //01 00 
		$a_00_1 = {73 61 76 65 74 6f 66 69 6c 65 20 45 6e 76 69 72 6f 6e 28 22 50 55 42 4c 49 43 22 29 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 5c 6c 61 75 6e 63 68 65 72 2e 70 73 31 } //01 00  savetofile Environ("PUBLIC") & "\Documents\launcher.ps1
		$a_00_2 = {3d 20 4e 6f 77 28 29 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 30 3a 30 30 3a 30 32 22 29 } //01 00  = Now() + TimeValue("00:00:02")
		$a_00_3 = {6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //01 00  objWMIService.Get("Win32_ProcessStartup")
		$a_00_4 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 72 65 6d 6f 74 65 73 69 67 6e 65 64 20 2d 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6c 61 75 6e 63 68 65 72 2e 70 73 31 } //00 00  powershell -executionpolicy remotesigned -File C:\Users\Public\Documents\launcher.ps1
	condition:
		any of ($a_*)
 
}