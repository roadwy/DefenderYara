
rule TrojanDownloader_O97M_Ursnif_FTIY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.FTIY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 69 6f 20 3d 20 6b 6f 3a 20 52 75 6e 20 28 22 22 20 26 20 22 41 22 20 26 20 33 29 } //01 00  nio = ko: Run ("" & "A" & 3)
		$a_01_1 = {46 6f 72 20 45 61 63 68 20 7a 61 61 20 49 6e 20 43 68 61 72 74 53 73 28 22 22 20 26 20 43 65 6c 6c 73 28 38 30 2c 20 34 29 2c 20 33 29 } //01 00  For Each zaa In ChartSs("" & Cells(80, 4), 3)
		$a_01_2 = {42 69 6f 45 6e 69 6d 61 20 3d 20 53 70 6c 69 74 28 54 6b 2c 20 22 79 22 29 } //01 00  BioEnima = Split(Tk, "y")
		$a_01_3 = {64 5f 6b 6f 20 3d 20 22 63 22 3a 20 64 5f 6b 6f 20 3d 20 22 3d 22 } //01 00  d_ko = "c": d_ko = "="
		$a_01_4 = {53 68 65 65 74 73 28 31 29 2e 5b 41 35 5d 2e 46 6f 72 6d 75 6c 61 4c 6f 63 61 6c 20 3d 20 71 71 } //01 00  Sheets(1).[A5].FormulaLocal = qq
		$a_01_5 = {52 6a 4c 20 3d 20 52 6a 4c 20 2b 20 31 } //00 00  RjL = RjL + 1
	condition:
		any of ($a_*)
 
}