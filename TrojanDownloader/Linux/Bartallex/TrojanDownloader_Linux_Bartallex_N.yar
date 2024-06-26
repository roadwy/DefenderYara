
rule TrojanDownloader_Linux_Bartallex_N{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.N,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 24 28 31 30 35 29 20 26 20 43 68 72 24 28 31 31 30 29 20 26 20 43 68 72 24 28 34 36 29 20 26 20 43 68 72 24 28 39 39 29 20 26 20 43 68 72 24 28 31 31 31 29 } //01 00  Chr$(105) & Chr$(110) & Chr$(46) & Chr$(99) & Chr$(111)
		$a_03_1 = {45 6e 76 69 72 6f 6e 28 90 02 10 29 20 26 20 22 5c 90 02 10 2e 76 62 73 90 00 } //01 00 
		$a_01_2 = {3d 20 22 65 6c 6c 2e 41 70 22 } //01 00  = "ell.Ap"
		$a_01_3 = {3d 20 22 63 61 74 69 22 } //01 00  = "cati"
		$a_03_4 = {3d 20 22 53 68 22 20 2b 20 90 02 0a 20 2b 20 22 70 6c 69 22 20 2b 20 90 02 0a 20 2b 20 22 6f 6e 22 90 00 } //01 00 
		$a_01_5 = {3d 20 22 32 2e 58 4d 22 } //01 00  = "2.XM"
		$a_01_6 = {3d 20 22 53 58 22 } //00 00  = "SX"
		$a_00_7 = {5d 04 00 } //00 a9 
	condition:
		any of ($a_*)
 
}