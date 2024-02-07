
rule TrojanDownloader_O97M_Donoff_I{
	meta:
		description = "TrojanDownloader:O97M/Donoff.I,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 7a 61 70 74 6f 2e 6f 72 67 3a } //01 00  .zapto.org:
		$a_02_1 = {2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 0d 0a 20 90 02 0f 2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_I_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.I,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2b 20 22 61 6e 64 45 6e 22 20 2b 20 22 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 22 } //01 00  + "andEn" + "vironmentStrings"
		$a_00_1 = {2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 25 74 65 6d 70 25 22 29 } //01 00  , VbMethod, "%temp%")
		$a_00_2 = {22 5c 77 61 72 61 6e 74 2e 65 78 65 22 } //01 00  "\warant.exe"
		$a_00_3 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  = VBA.CreateObject("WScript.Shell")
		$a_00_4 = {22 52 75 6e 22 2c 20 56 62 4d 65 74 68 6f 64 2c } //00 00  "Run", VbMethod,
		$a_00_5 = {8f b2 00 } //00 10 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_I_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.I,SIGNATURE_TYPE_MACROHSTR_EXT,10 00 10 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 41 73 63 28 4d 69 64 28 } //02 00  = Asc(Mid(
		$a_01_1 = {26 20 43 68 72 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 28 } //02 00  & Chr(Val("&H" & Mid(
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 65 70 6c 61 63 65 28 22 } //01 00  = CreateObject(Replace("
		$a_01_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //02 00  Sub AutoOpen()
		$a_01_4 = {2e 4c 61 6e 67 75 61 67 65 20 3d 20 22 6a 73 63 72 69 70 74 22 } //04 00  .Language = "jscript"
		$a_01_5 = {3d 20 22 33 63 31 30 30 36 34 65 32 36 33 61 31 35 34 31 30 61 36 61 35 36 } //04 00  = "3c10064e263a15410a6a56
		$a_01_6 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 47 72 72 51 52 6e 62 28 } //00 00  Public Function GrrQRnb(
		$a_00_7 = {8f b5 00 00 01 } //00 01 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_I_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.I,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 62 77 67 72 47 55 49 75 7a 69 20 3d 20 67 68 57 6d 42 6b 31 52 67 63 36 45 58 34 28 43 68 72 28 38 37 29 20 26 20 43 68 72 28 38 33 29 20 26 20 43 68 72 28 39 39 29 20 26 20 43 68 72 28 31 31 34 29 20 26 20 43 68 72 28 31 30 35 29 20 26 20 43 68 72 28 31 31 32 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 38 33 29 20 26 20 43 68 72 28 31 30 34 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 31 30 38 29 20 26 20 43 68 72 28 31 30 38 29 29 } //00 00  Set bwgrGUIuzi = ghWmBk1Rgc6EX4(Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116) & Chr(46) & Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108))
	condition:
		any of ($a_*)
 
}