
rule TrojanDownloader_O97M_Ursnif_PDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 28 28 28 28 28 28 28 28 28 28 22 22 20 26 20 22 49 22 20 26 20 74 70 20 26 20 22 22 29 29 29 29 29 } //01 00  Run(((((((((("" & "I" & tp & "")))))
		$a_01_1 = {3d 20 53 70 6c 69 74 28 68 69 6f 54 2c 20 22 3f 22 29 } //01 00  = Split(hioT, "?")
		$a_01_2 = {53 68 65 65 74 73 28 6d 73 6f 4c 69 6e 65 53 69 6e 67 6c 65 29 2e 43 65 6c 6c 73 28 33 30 20 2b 20 37 2c 20 33 20 2a 20 33 29 2e 46 6f 72 6d 75 6c 61 4c 6f 63 61 6c 20 3d 20 56 56 6f 6f 20 26 20 66 6f 72 63 65 72 } //01 00  Sheets(msoLineSingle).Cells(30 + 7, 3 * 3).FormulaLocal = VVoo & forcer
		$a_01_3 = {3d 20 56 6d 6f 72 65 28 30 20 2b 20 79 2c 20 22 22 20 26 20 79 20 2b 20 37 29 3a 20 68 4b 69 6f } //01 00  = Vmore(0 + y, "" & y + 7): hKio
		$a_01_4 = {3d 20 66 20 26 20 43 61 50 6f 6f 28 22 22 20 26 20 70 2c 20 70 2e 43 6f 6c 75 6d 6e 29 } //00 00  = f & CaPoo("" & p, p.Column)
	condition:
		any of ($a_*)
 
}