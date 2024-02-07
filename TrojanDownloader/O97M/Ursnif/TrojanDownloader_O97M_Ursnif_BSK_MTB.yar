
rule TrojanDownloader_O97M_Ursnif_BSK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.BSK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 28 28 28 28 28 28 28 28 28 28 22 4f 22 20 26 20 22 34 22 20 26 20 22 22 29 } //01 00  Run(((((((((("O" & "4" & "")
		$a_01_1 = {3d 20 53 70 6c 69 74 28 65 73 70 65 72 69 65 6e 7a 61 41 2c 20 22 7a 22 29 } //01 00  = Split(esperienzaA, "z")
		$a_03_2 = {3d 20 70 6f 74 72 65 6d 6d 6f 28 30 20 2b 20 90 02 12 2c 20 22 22 20 26 20 90 02 12 29 3a 20 72 69 67 75 61 72 64 61 90 00 } //01 00 
		$a_01_3 = {53 68 65 65 74 73 28 6d 73 6f 47 72 61 64 69 65 6e 74 48 6f 72 69 7a 6f 6e 74 61 6c 29 2e 43 65 6c 6c 73 28 33 37 2c 20 31 35 29 2e 46 6f 72 6d 75 6c 61 4c 6f 63 61 6c 20 3d } //00 00  Sheets(msoGradientHorizontal).Cells(37, 15).FormulaLocal =
	condition:
		any of ($a_*)
 
}