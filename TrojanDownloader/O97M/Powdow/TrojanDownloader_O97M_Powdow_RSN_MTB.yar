
rule TrojanDownloader_O97M_Powdow_RSN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 38 34 34 6b 71 38 70 6c 31 2e 6a 70 67 90 0a 40 00 44 6f 77 27 2b 27 6e 6c 27 2b 27 6f 61 64 27 2b 27 46 69 6c 27 2b 27 65 28 27 27 68 74 74 70 73 3a 2f 2f 90 00 } //01 00 
		$a_00_1 = {73 74 61 72 74 2d 70 72 6f 63 65 73 73 28 24 65 6e 76 3a 41 50 50 44 41 54 41 2b 27 5c 5c 27 2b 27 70 61 6e 64 6f 72 69 6e 68 61 2e 76 62 73 27 29 } //01 00  start-process($env:APPDATA+'\\'+'pandorinha.vbs')
		$a_00_2 = {52 65 70 6c 61 63 65 28 61 2c 20 22 23 7c 50 61 6e 64 6f 72 69 6e 68 61 7c 23 22 2c 20 22 20 22 29 } //01 00  Replace(a, "#|Pandorinha|#", " ")
		$a_00_3 = {62 6f 6c 6f 74 61 20 3d 20 62 20 26 20 63 20 26 20 22 77 65 72 73 68 65 6c 6c 22 20 26 20 61 } //01 00  bolota = b & c & "wershell" & a
		$a_00_4 = {6f 62 6a 71 63 79 64 77 79 71 6e 6f 7a 6a 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 65 61 6f 61 73 75 6e 6c 6b 6d 2c 20 30 } //00 00  objqcydwyqnozj.CreateObject("WScript.Shell").Run eaoasunlkm, 0
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_RSN_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 32 30 32 31 2e 6a 50 47 90 0a 47 00 44 6f 77 27 2b 27 6e 6c 27 2b 27 6f 61 64 27 2b 27 46 69 6c 27 2b 27 65 28 27 27 68 74 74 70 73 3a 2f 2f 90 00 } //01 00 
		$a_00_1 = {73 74 61 72 74 2d 70 72 6f 63 65 73 73 28 24 65 6e 76 3a 41 50 50 44 41 54 41 2b 27 5c 5c 27 2b 27 6a 65 66 69 6e 68 6f 63 75 64 65 73 61 70 6f 2e 6a 73 27 } //01 00  start-process($env:APPDATA+'\\'+'jefinhocudesapo.js'
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 65 61 6f 61 73 75 6e 6c 6b 6d 2c 20 30 } //01 00  CreateObject("WScript.Shell").Run eaoasunlkm, 0
		$a_00_3 = {53 65 74 20 6f 62 6a 71 63 79 64 77 79 71 6e 6f 7a 6a 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 22 20 26 20 4f 55 54 4c 4f 4f 4b 29 } //01 00  Set objqcydwyqnozj = GetObject("new:" & OUTLOOK)
		$a_00_4 = {62 6f 6c 6f 74 61 20 3d 20 62 20 26 20 63 20 26 20 22 77 65 72 73 68 65 6c 6c 22 20 26 20 61 } //00 00  bolota = b & c & "wershell" & a
	condition:
		any of ($a_*)
 
}