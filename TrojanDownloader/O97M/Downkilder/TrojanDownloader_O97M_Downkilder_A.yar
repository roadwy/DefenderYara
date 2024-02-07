
rule TrojanDownloader_O97M_Downkilder_A{
	meta:
		description = "TrojanDownloader:O97M/Downkilder.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 68 65 65 74 73 28 22 53 54 41 52 54 22 29 2e 56 69 73 69 62 6c 65 20 3d 20 78 6c 56 65 72 79 48 69 64 64 65 6e } //01 00  Sheets("START").Visible = xlVeryHidden
		$a_00_1 = {66 6e 61 6d 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 22 } //01 00  fname = Environ("TMP") & "\explorer.exe"
		$a_00_2 = {72 73 73 20 3d 20 53 68 65 6c 6c 28 66 6e 61 6d 65 2c 20 31 29 } //00 00  rss = Shell(fname, 1)
	condition:
		any of ($a_*)
 
}