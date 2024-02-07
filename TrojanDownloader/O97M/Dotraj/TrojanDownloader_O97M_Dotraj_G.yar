
rule TrojanDownloader_O97M_Dotraj_G{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.G,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 05 a0 0b 61 2d 7a 41 2d 5a 30 2d 39 20 2b 29 2e 52 75 6e 90 02 01 28 90 05 01 01 28 22 22 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 2e 54 65 78 74 42 6f 78 31 29 90 00 } //01 00 
		$a_00_1 = {77 73 63 72 69 70 74 2e 73 68 65 6c 6c } //00 00  wscript.shell
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dotraj_G_2{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.G,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {5b 72 75 6e 74 69 6d 65 2e 69 6e 74 65 72 6f 70 73 65 72 76 69 63 65 73 2e 6d 61 72 73 68 61 6c 5d 2e 67 65 74 6d 65 6d 62 65 72 73 28 29 5b 34 5d 2e 6e 61 6d 65 29 2e 69 6e 76 6f 6b 65 28 20 5b 72 75 6e 74 69 6d 65 2e 69 6e 74 65 72 6f 70 73 65 72 76 69 63 65 73 2e 6d 61 72 73 68 61 6c 5d 3a 3a 73 65 63 75 72 65 73 74 72 69 6e 67 74 6f 67 6c 71 6a } //01 00  [runtime.interopservices.marshal].getmembers()[4].name).invoke( [runtime.interopservices.marshal]::securestringtoglqj
		$a_02_1 = {20 3d 20 43 6f 73 28 90 10 08 00 20 2d 20 4f 63 74 28 90 10 08 00 20 2b 20 90 1d 09 00 20 2a 20 90 1d 09 00 20 2d 20 43 42 6f 6f 6c 28 90 1d 09 00 29 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dotraj_G_3{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.G,SIGNATURE_TYPE_MACROHSTR_EXT,29 00 28 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  CreateObject("shell.application")
		$a_00_1 = {53 65 6c 65 63 74 69 6f 6e 2e 54 79 70 65 54 65 78 74 20 28 } //01 00  Selection.TypeText (
		$a_00_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 73 73 77 6f 72 64 20 3d 20 } //0a 00  ActiveDocument.Password = 
		$a_02_3 = {49 66 20 4e 6f 74 20 22 90 1d 20 00 22 20 4c 69 6b 65 20 90 02 10 20 54 68 65 6e 90 00 } //0a 00 
		$a_02_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 63 6d 64 2e 65 78 65 22 2c 20 90 02 20 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 30 90 00 } //0a 00 
		$a_02_5 = {46 6f 72 20 90 02 20 20 3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 90 20 26 20 90 02 10 28 4d 69 64 28 90 02 30 2c 20 31 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}