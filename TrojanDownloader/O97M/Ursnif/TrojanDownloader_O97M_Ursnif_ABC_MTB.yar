
rule TrojanDownloader_O97M_Ursnif_ABC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.ABC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 6f 20 3d 20 79 65 70 3a 20 52 75 6e 20 28 22 22 20 26 20 22 41 22 20 26 20 33 29 } //1 ro = yep: Run ("" & "A" & 3)
		$a_01_1 = {45 78 63 65 6c 34 4d 61 63 72 6f 53 68 65 65 74 73 2e 41 64 64 28 42 65 66 6f 72 65 3a 3d 57 6f 72 6b 73 68 65 65 74 73 28 28 31 29 29 29 2e 4e 61 6d 65 20 3d 20 4c 6f 77 65 3a 20 46 69 73 6f 6c 6f } //1 Excel4MacroSheets.Add(Before:=Worksheets((1))).Name = Lowe: Fisolo
		$a_01_2 = {73 20 3d 20 73 3a 20 53 68 65 65 74 73 28 31 29 2e 5b 41 35 5d 2e 46 6f 72 6d 75 6c 61 4c 6f 63 61 6c 20 3d 20 65 64 } //1 s = s: Sheets(1).[A5].FormulaLocal = ed
		$a_01_3 = {56 61 73 44 65 6d 6f 20 3d 20 53 70 6c 69 74 28 69 2c 20 22 79 22 29 } //1 VasDemo = Split(i, "y")
		$a_01_4 = {46 75 6e 63 74 69 6f 6e 20 68 68 69 65 69 67 68 28 29 } //1 Function hhieigh()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}