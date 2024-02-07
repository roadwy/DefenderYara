
rule TrojanDownloader_O97M_Powdow_SMA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4d 6f 64 75 6c 65 31 31 22 90 02 03 53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 90 02 03 4d 73 67 42 6f 78 20 22 45 72 72 6f 72 21 21 90 00 } //01 00 
		$a_01_1 = {53 65 74 20 6f 62 6a 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  Set objShell = CreateObject("Shell.Application")
		$a_03_2 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 90 02 25 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}