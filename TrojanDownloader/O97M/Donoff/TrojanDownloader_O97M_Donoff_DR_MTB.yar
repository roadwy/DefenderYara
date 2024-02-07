
rule TrojanDownloader_O97M_Donoff_DR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 44 33 56 49 35 48 34 2f 46 4c 41 4d 45 53 2f 62 6c 6f 62 2f 6d 61 69 6e 2f 44 61 74 61 25 32 30 45 78 66 69 6c 74 72 61 74 6f 72 2e 65 78 65 22 90 0a 44 00 22 68 74 74 70 73 3a 2f 2f 90 00 } //01 00 
		$a_01_1 = {44 65 73 6b 74 6f 70 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 53 65 70 61 72 61 74 6f 72 20 26 } //01 00  Desktop" & Application.PathSeparator &
		$a_01_2 = {66 69 6c 65 2e 65 78 65 22 } //01 00  file.exe"
		$a_01_3 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 6d 79 55 52 4c 2c 20 46 61 6c 73 65 } //01 00  .Open "GET", myURL, False
		$a_01_4 = {57 69 6e 48 74 74 70 52 65 71 2e 53 65 6e 64 } //01 00  WinHttpReq.Send
		$a_01_5 = {53 68 65 6c 6c 28 22 43 3a 5c 57 49 4e 44 4f 57 53 5c 4e 4f 54 45 50 41 44 2e 45 58 45 22 2c 20 31 29 } //00 00  Shell("C:\WINDOWS\NOTEPAD.EXE", 1)
	condition:
		any of ($a_*)
 
}