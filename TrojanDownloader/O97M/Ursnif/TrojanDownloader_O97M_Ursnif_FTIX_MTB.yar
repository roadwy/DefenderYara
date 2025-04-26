
rule TrojanDownloader_O97M_Ursnif_FTIX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.FTIX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6f 50 68 6f 20 3d 20 64 5f 6b 6f 20 26 20 22 52 22 20 26 20 22 49 22 } //1 soPho = d_ko & "R" & "I"
		$a_01_1 = {53 77 20 3d 20 34 3a 20 53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 31 37 2c 20 31 29 2e 46 6f 72 6d 75 6c 61 4c 6f 63 61 6c 20 3d 20 73 6f 50 68 6f 20 26 20 52 6f 75 6e 74 73 } //1 Sw = 4: Sheets(1).Cells(17, 1).FormulaLocal = soPho & Rounts
		$a_01_2 = {45 78 63 65 6c 34 4d 61 63 72 6f 53 68 65 65 74 73 2e 41 64 64 20 42 65 66 6f 72 65 3a 3d 57 6f 72 6b 73 68 65 65 74 73 28 74 6f 6c 29 3a 20 65 6d 6d } //1 Excel4MacroSheets.Add Before:=Worksheets(tol): emm
		$a_01_3 = {74 62 20 3d 20 35 3a 20 6d 74 68 68 20 3d 20 28 68 61 42 69 69 28 64 5f 6b 6f 20 26 20 66 6b 2c 20 31 20 2b 20 74 62 29 29 3a 20 78 20 3d 20 74 6f 6c 3a 20 72 65 6d 6d 69 6f 73 66 20 28 31 31 32 29 } //1 tb = 5: mthh = (haBii(d_ko & fk, 1 + tb)): x = tol: remmiosf (112)
		$a_01_4 = {56 61 61 72 6d 69 20 3d 20 63 6f 70 70 50 20 26 20 22 52 4e 22 } //1 Vaarmi = coppP & "RN"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}