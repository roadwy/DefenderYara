
rule TrojanDownloader_Linux_Donoff{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,2b 00 2b 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 5f 4f 70 65 6e } //01 00  Auto_Open
		$a_01_1 = {43 68 72 28 31 } //01 00  Chr(1
		$a_01_2 = {43 68 72 28 34 } //01 00  Chr(4
		$a_01_3 = {53 67 6e 28 } //0a 00  Sgn(
		$a_01_4 = {22 20 2b 20 22 22 20 2b 20 22 } //0a 00  " + "" + "
		$a_01_5 = {22 20 26 20 22 } //0a 00  " & "
		$a_01_6 = {2e 4f 70 65 6e 20 22 47 45 54 22 } //00 00  .Open "GET"
		$a_00_7 = {8f 59 00 00 01 00 01 00 01 00 00 01 00 4c 01 68 42 71 74 66 74 70 69 71 3a 2f 52 66 2f 68 42 66 70 } //73 71 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_2{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 42 71 74 66 74 70 69 71 3a 2f 52 66 2f 68 42 66 70 73 71 61 71 66 7a 2e 69 69 63 71 6f 71 6d 2f 71 69 73 35 79 73 69 66 74 35 65 6d 42 52 2f 71 63 71 61 63 56 42 68 35 65 35 2f 69 77 71 6f 72 52 56 64 42 2e 65 35 66 78 65 52 } //00 00  hBqtftpiq:/Rf/hBfpsqaqfz.iicqoqm/qis5ysift5emBR/qcqacVBh5e5/iwqorRVdB.e5fxeR
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_3{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 32 38 30 2f 34 36 61 75 2e 65 78 65 } //01 00  :280/46au.exe
		$a_01_1 = {22 54 4d 50 22 29 20 26 20 22 5c 4c 57 47 4b 41 49 2e 65 78 65 } //01 00  "TMP") & "\LWGKAI.exe
		$a_01_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 41 75 74 6f 5f 4f 70 65 6e 0d 0a 45 6e 64 20 53 75 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_4{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 90 02 40 3a 90 02 05 2f 90 02 10 2e 65 78 65 90 00 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //01 00  URLDownloadToFile
		$a_01_2 = {41 75 74 6f 5f 4f 70 65 6e } //01 00  Auto_Open
		$a_01_3 = {45 6e 76 69 72 6f 6e } //01 00  Environ
		$a_01_4 = {53 68 65 6c 6c } //00 00  Shell
		$a_00_5 = {8f 6f 00 00 } //04 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_5{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 6f 74 2e 6a 61 72 } //01 00  bot.jar
		$a_01_1 = {45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 20 26 20 22 5c 22 20 26 } //01 00  Environ$("tmp") & "\" &
		$a_01_2 = {43 68 61 6e 67 65 54 65 78 74 20 30 2c 20 22 6f 70 65 6e 22 2c 20 5f } //01 00  ChangeText 0, "open", _
		$a_00_3 = {22 69 6e 76 6f 69 63 65 2e 6a 61 72 22 } //01 00  "invoice.jar"
		$a_01_4 = {3d 20 22 31 39 32 2e 39 39 2e 31 38 31 2e } //00 00  = "192.99.181.
		$a_00_5 = {8f 7f } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_6{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 72 52 65 76 65 72 73 65 28 48 65 78 32 53 74 72 28 22 35 34 34 35 34 37 22 29 29 } //01 00  StrReverse(Hex2Str("544547"))
		$a_01_1 = {48 65 78 32 53 74 72 28 22 36 38 37 34 37 34 37 30 33 41 32 46 32 46 33 32 33 34 33 37 36 36 36 39 36 45 36 31 36 45 36 33 36 35 36 34 36 35 36 31 36 43 32 45 36 33 36 46 36 44 32 46 36 34 36 32 37 35 37 33 37 34 32 45 36 35 37 38 36 35 22 29 } //00 00  Hex2Str("687474703A2F2F32343766696E616E63656465616C2E636F6D2F64627573742E657865")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_7{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 4f 70 65 6e 90 02 0c 28 37 31 29 90 02 0c 28 36 39 29 90 02 0c 28 38 34 29 90 02 0c 28 31 30 34 29 90 02 0c 28 31 31 36 29 90 00 } //01 00 
		$a_01_1 = {2e 77 72 69 74 65 } //01 00  .write
		$a_01_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 } //01 00  .savetofile
		$a_01_3 = {2e 54 79 70 65 } //01 00  .Type
		$a_01_4 = {2e 45 6e 76 69 72 6f 6e } //01 00  .Environ
		$a_03_5 = {28 34 36 29 90 02 0c 28 31 30 31 29 90 02 20 28 31 30 31 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_8{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 70 75 74 65 72 20 3d 20 41 72 72 61 79 28 } //01 00  computer = Array(
		$a_03_1 = {72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 66 72 6f 6d 41 72 72 28 69 29 20 2d 20 90 02 04 20 2b 20 69 29 90 00 } //01 00 
		$a_00_2 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 63 6f 6d 70 75 74 65 72 29 2c 20 46 61 6c 73 65 } //00 00  Open "GET", GetStringFromArray(computer), False
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_9{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 43 44 46 20 3d 20 50 55 76 64 20 2b 20 75 42 49 6e 7a 7a 4f 53 56 4e 6d 42 75 65 4c 4f 6a 4c 50 65 28 90 02 10 29 20 2b 20 45 45 57 45 46 20 2b 20 75 42 49 6e 7a 7a 4f 53 56 4e 6d 42 75 65 4c 4f 6a 4c 50 65 28 90 00 } //01 00 
		$a_01_1 = {43 61 6c 6c 20 50 50 75 69 79 66 68 46 73 64 66 2e 4f 70 65 6e 28 75 42 49 6e 7a 7a 4f 53 56 4e 6d 42 75 65 4c 4f 6a 4c 50 65 28 22 5d 5c 60 61 22 29 2c 20 43 43 44 46 2c 20 46 61 6c 73 65 29 } //00 00  Call PPuiyfhFsdf.Open(uBInzzOSVNmBueLOjLPe("]\`a"), CCDF, False)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_10{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 10 2e 54 65 78 74 42 6f 78 90 00 } //01 00 
		$a_03_1 = {2e 4f 70 65 6e 20 90 02 10 2e 54 65 78 74 42 6f 78 90 02 01 2c 20 90 02 10 2e 54 65 78 74 42 6f 78 90 02 01 2c 20 46 61 6c 73 65 90 00 } //01 00 
		$a_03_2 = {45 6e 76 69 72 6f 6e 28 90 02 10 2e 54 65 78 74 42 6f 78 90 02 01 29 20 26 20 22 2f 6b 66 63 22 20 2b 20 90 02 10 2e 54 65 78 74 42 6f 78 90 00 } //01 00 
		$a_03_3 = {3d 20 53 68 65 6c 6c 28 90 02 10 2e 54 65 78 74 42 6f 78 90 00 } //00 00 
		$a_00_4 = {8f b1 00 } //00 06 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_11{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 4f 70 65 6e 90 02 0c 28 37 31 29 90 02 20 28 31 30 34 29 90 02 20 28 31 31 36 29 90 00 } //01 00 
		$a_01_1 = {2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //01 00  .responseBody
		$a_03_2 = {28 34 36 29 90 02 0c 28 31 30 31 29 90 02 20 28 31 30 31 29 90 00 } //01 00 
		$a_03_3 = {28 38 34 29 90 02 20 28 38 30 29 90 00 } //01 00 
		$a_02_4 = {28 38 33 29 90 02 0c 28 31 30 34 29 90 02 0c 28 31 30 31 29 90 02 0c 28 31 30 38 29 90 02 0c 28 31 30 38 29 90 00 } //01 00 
		$a_03_5 = {28 31 30 31 29 90 02 20 28 31 30 30 29 90 02 10 56 62 4d 65 74 68 6f 64 90 00 } //00 00 
		$a_00_6 = {8f b4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_12{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 53 70 6c 69 74 28 22 90 02 20 2e 90 02 03 2f 38 37 74 33 34 66 2b 90 02 20 2e 90 02 03 2f 38 37 74 33 34 66 2b 90 02 20 2e 90 02 03 2f 38 37 74 33 34 66 22 2c 20 66 69 72 6d 2e 42 6f 72 4c 62 6c 2e 43 61 70 74 69 6f 6e 29 90 00 } //01 00 
		$a_03_1 = {22 73 22 20 2b 20 90 11 05 00 90 02 15 20 2b 20 22 69 6c 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 90 00 } //01 00 
		$a_03_2 = {52 65 70 6c 61 63 65 28 90 02 15 28 31 32 29 2c 20 22 2e 22 2c 20 43 53 74 72 28 50 72 6f 6a 65 63 74 90 02 0a 29 20 2b 20 22 2e 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_13{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 53 6f 72 72 79 } //01 00  Call Sorry
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 20 30 26 2c 20 53 74 72 50 74 72 28 52 65 70 6c 61 63 65 28 53 68 61 7a 61 6d 2c 20 22 7c 22 2c 20 22 22 29 29 2c } //01 00  URLDownloadToFileW 0&, StrPtr(Replace(Shazam, "|", "")),
		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 20 30 26 2c 20 53 74 72 50 74 72 28 22 4f 70 65 6e 22 29 2c 20 53 74 72 50 74 72 28 53 6b 79 70 65 29 2c } //01 00  ShellExecuteW 0&, StrPtr("Open"), StrPtr(Skype),
		$a_01_3 = {22 50 6f 72 20 66 61 76 6f 72 20 6c 65 20 73 6f 6c 69 63 69 74 61 6d 6f 73 20 71 75 65 20 69 67 6e 6f 72 65 20 65 73 74 65 20 63 6f 72 72 65 6f 2f 64 6f 63 75 6d 65 6e 74 6f 2e 22 } //00 00  "Por favor le solicitamos que ignore este correo/documento."
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_14{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {28 31 30 34 29 90 02 10 74 90 02 10 43 68 72 28 31 31 36 29 90 02 10 70 90 02 10 28 35 38 29 90 00 } //01 00 
		$a_02_1 = {28 34 36 29 90 02 0c 28 31 30 31 29 90 02 0c 28 31 32 30 29 90 02 0c 28 31 30 31 29 90 00 } //01 00 
		$a_02_2 = {28 37 39 29 90 02 0c 28 31 31 32 29 90 02 20 28 31 30 31 29 90 02 20 28 31 31 30 29 90 00 } //01 00 
		$a_02_3 = {28 37 31 29 90 02 0c 28 36 39 29 90 02 20 28 38 34 29 90 00 } //01 00 
		$a_02_4 = {28 38 34 29 90 02 0c 28 36 39 29 90 02 20 28 37 37 29 90 02 20 28 38 30 29 90 00 } //01 00 
		$a_02_5 = {28 31 31 30 29 90 02 0c 28 31 31 38 29 90 02 20 28 31 30 35 29 90 02 20 28 31 31 30 29 90 00 } //01 00 
		$a_02_6 = {28 31 30 30 29 90 02 0c 6d 90 02 20 28 31 30 35 29 90 02 20 28 31 31 30 29 90 00 } //00 00 
		$a_00_7 = {8f ee 00 00 } //0c 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_15{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 0b 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 3d 20 22 6e 74 72 22 90 0b 00 00 90 00 } //01 00 
		$a_03_1 = {3d 20 22 63 72 69 22 90 0b 00 00 90 00 } //01 00 
		$a_03_2 = {3d 20 22 72 69 70 22 90 0b 00 00 90 00 } //01 00 
		$a_03_3 = {3d 20 22 6f 6e 74 22 90 0b 00 00 90 00 } //01 00 
		$a_03_4 = {3d 20 22 4a 53 63 22 90 0b 00 00 90 00 } //01 00 
		$a_03_5 = {3d 20 22 74 43 6f 22 90 0b 00 00 90 00 } //01 00 
		$a_03_6 = {3d 20 22 72 6f 6c 22 90 0b 00 00 90 00 } //01 00 
		$a_03_7 = {3d 20 22 2e 53 63 22 90 0b 00 00 90 00 } //01 00 
		$a_03_8 = {3d 20 22 4d 53 53 22 90 0b 00 00 90 00 } //01 00 
		$a_03_9 = {3d 20 22 70 74 43 22 20 90 0b 00 00 90 00 } //03 00 
		$a_03_10 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 11 06 00 29 90 01 0a 90 02 04 2e 4c 61 6e 67 75 61 67 65 20 3d 20 90 01 10 90 02 06 2e 45 76 61 6c 20 28 90 00 } //00 00 
		$a_00_11 = {8f 2e 01 00 02 } //00 02 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_16{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 44 68 41 58 6d 65 6d 53 32 37 38 42 36 20 3d 20 66 41 51 61 56 47 4a 66 43 59 55 4c 28 43 68 72 28 37 37 29 20 26 20 22 69 22 20 26 20 43 68 72 28 39 39 29 20 26 20 43 68 72 28 31 31 34 29 20 26 20 22 6f 22 20 26 20 43 68 72 28 31 31 35 29 20 26 20 43 68 72 28 31 31 31 29 20 26 20 43 68 72 28 31 30 32 29 20 26 20 22 74 22 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 38 38 29 20 26 20 22 4d 22 20 26 20 22 4c 22 20 26 20 22 48 22 20 26 20 43 68 72 28 38 34 29 20 26 20 43 68 72 28 38 34 29 20 26 20 43 68 72 28 38 30 29 29 } //01 00  Set DhAXmemS278B6 = fAQaVGJfCYUL(Chr(77) & "i" & Chr(99) & Chr(114) & "o" & Chr(115) & Chr(111) & Chr(102) & "t" & Chr(46) & Chr(88) & "M" & "L" & "H" & Chr(84) & Chr(84) & Chr(80))
		$a_01_1 = {43 61 6c 6c 42 79 4e 61 6d 65 20 44 68 41 58 6d 65 6d 53 32 37 38 42 36 2c 20 22 4f 22 20 26 20 43 68 72 28 31 31 32 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 31 31 30 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 43 68 72 28 37 31 29 20 26 20 43 68 72 28 36 39 29 20 26 20 43 68 72 28 38 34 29 2c 20 5f } //00 00  CallByName DhAXmemS278B6, "O" & Chr(112) & Chr(101) & Chr(110), VbMethod, Chr(71) & Chr(69) & Chr(84), _
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Donoff_17{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 90 12 0f 00 28 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 56 61 72 69 61 6e 74 90 00 } //02 00 
		$a_03_1 = {4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 90 02 1f 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 90 02 1f 3d 90 02 1f 45 78 69 74 20 46 75 6e 63 74 69 6f 6e 90 02 1f 3a 90 02 1f 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 90 00 } //02 00 
		$a_03_2 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 90 12 0f 00 28 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 56 61 72 69 61 6e 74 29 20 41 73 20 56 61 72 69 61 6e 74 90 00 } //02 00 
		$a_03_3 = {28 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 4f 62 6a 65 63 74 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 56 61 72 69 61 6e 74 90 02 30 29 90 02 04 43 61 6c 6c 42 79 4e 61 6d 65 20 90 1b 00 2c 20 90 1b 01 2c 20 31 2c 20 90 1b 02 90 00 } //02 00 
		$a_03_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 0f 28 22 90 02 0f 2e 90 02 0f 22 2c 20 90 01 03 29 29 90 00 } //01 00 
		$a_01_5 = {45 72 72 2e 52 61 69 73 65 20 4e 75 6d 62 65 72 3a 3d 31 } //00 00  Err.Raise Number:=1
	condition:
		any of ($a_*)
 
}