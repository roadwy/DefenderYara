
rule TrojanDownloader_O97M_Obfuse_FX{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FX,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 12 28 90 02 14 29 20 26 20 90 02 12 28 90 02 16 29 29 2e 52 75 6e 20 90 02 15 2c 20 30 90 00 } //01 00 
		$a_03_1 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 90 02 12 2c 20 90 02 12 2c 20 32 29 29 29 90 00 } //01 00 
		$a_01_2 = {43 61 6c 6c 20 55 6e 68 69 64 65 53 68 65 65 74 73 } //01 00  Call UnhideSheets
		$a_01_3 = {53 68 65 65 74 73 28 22 50 72 6f 6d 70 74 22 29 2e 56 69 73 69 62 6c 65 20 3d 20 78 6c 53 68 65 65 74 56 65 72 79 48 69 64 64 65 6e } //00 00  Sheets("Prompt").Visible = xlSheetVeryHidden
	condition:
		any of ($a_*)
 
}