
rule TrojanDownloader_O97M_EncDoc_ASMG_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ASMG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 79 55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 72 65 64 63 61 72 2d 65 6c 65 63 74 72 6f 6e 69 63 73 2e 63 6f 2e 75 6b 2f 64 6f 77 6e 6c 6f 61 64 2f 68 6f 73 74 2e 65 78 65 } //01 00  myURL = "https://www.redcar-electronics.co.uk/download/host.exe
		$a_01_1 = {66 69 6c 65 54 6f 4c 61 75 6e 63 68 20 3d 20 22 43 3a 5c 53 79 73 74 65 6d 5c 31 2e 65 78 65 } //01 00  fileToLaunch = "C:\System\1.exe
		$a_01_2 = {53 68 65 6c 6c 20 66 69 6c 65 54 6f 4c 61 75 6e 63 68 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //00 00  Shell fileToLaunch, vbNormalFocus
	condition:
		any of ($a_*)
 
}