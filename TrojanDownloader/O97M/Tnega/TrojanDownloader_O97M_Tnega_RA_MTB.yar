
rule TrojanDownloader_O97M_Tnega_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Tnega.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 20 22 6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 42 61 73 65 36 34 44 65 63 6f 64 65 28 22 } //01 00  + "objShell.Run Base64Decode("
		$a_01_1 = {3d 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 77 22 20 2b 20 22 73 63 72 69 70 74 22 20 2b 20 22 2e 65 78 65 20 22 } //01 00  = "C:\Windows\System32\w" + "script" + ".exe "
		$a_01_2 = {22 57 53 63 72 69 70 74 2e 22 20 2b 20 22 53 68 65 22 20 2b 20 22 6c 6c 22 } //01 00  "WScript." + "She" + "ll"
		$a_03_3 = {2b 20 22 2e 22 20 2b 20 22 76 22 0d 0a 90 02 05 20 3d 20 90 1b 00 20 2b 20 22 62 73 22 90 00 } //00 00 
		$a_00_4 = {8f d8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Tnega_RA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Tnega.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 44 6c 6c 4e 61 6d 65 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 64 65 73 6b 74 6f 70 2e 64 61 74 22 } //01 00  GetDllName = "C:\ProgramData\desktop.dat"
		$a_01_1 = {2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 61 73 65 36 34 22 29 } //01 00  .CreateElement("base64")
		$a_03_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 0d 0a 20 20 20 20 90 02 0f 20 3d 20 4c 65 66 74 28 90 02 0f 2c 20 49 6e 53 74 72 52 65 76 28 90 02 0f 2c 20 22 2e 22 29 20 2d 20 31 29 90 00 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 6f 72 64 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //00 00  CreateObject("Word.Application")
	condition:
		any of ($a_*)
 
}