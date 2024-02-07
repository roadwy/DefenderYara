
rule TrojanDownloader_O97M_Obfuse_PKSW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PKSW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 43 51 55 2e 4f 70 65 6e 28 76 30 64 66 20 2b 20 22 5c 63 50 78 4e 58 2e 62 61 74 22 29 } //01 00  = SCQU.Open(v0df + "\cPxNX.bat")
		$a_01_1 = {20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 } //01 00   Environ("AppData")
		$a_03_2 = {20 3d 20 47 65 74 4f 62 6a 65 63 74 28 52 61 6e 67 65 28 22 90 02 05 22 29 2e 56 61 6c 75 65 29 90 00 } //01 00 
		$a_01_3 = {28 29 20 2b 20 22 5c 63 50 78 4e 58 2e 62 61 74 22 20 27 79 6f 75 20 63 61 6e 20 73 70 65 63 69 66 79 20 68 65 72 65 20 74 68 65 20 74 65 78 74 20 66 69 6c 65 20 6e 61 6d 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 72 65 61 74 65 } //00 00  () + "\cPxNX.bat" 'you can specify here the text file name you want to create
	condition:
		any of ($a_*)
 
}