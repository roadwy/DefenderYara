
rule TrojanDownloader_O97M_Dridex_AJU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.AJU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 56 42 41 37 20 41 6e 64 20 57 69 6e 36 34 20 54 68 65 6e } //1 #If VBA7 And Win64 Then
		$a_01_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 79 65 6c 6c 6f 77 5f 70 61 67 65 73 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 5f } //1 Private Declare PtrSafe Function yellow_pages Lib "urlmon" _
		$a_01_2 = {41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 20 5f } //1 Alias "URLDownloadToFileA" ( _
		$a_01_3 = {3d 20 53 70 6c 69 74 28 52 54 72 69 6d 28 66 69 72 73 74 5f 70 72 65 70 61 79 6d 65 6e 74 29 2c 20 70 72 6f 67 72 65 73 73 5f 62 61 72 73 28 22 29 22 29 29 } //1 = Split(RTrim(first_prepayment), progress_bars(")"))
		$a_01_4 = {53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 33 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 3d 22 20 26 20 73 74 6f 72 61 67 65 73 28 41 29 } //1 Sheets(1).Cells(3, 1).Value = "=" & storages(A)
		$a_01_5 = {52 75 6e 20 28 22 46 6f 72 41 5f 22 20 26 20 22 73 22 29 } //1 Run ("ForA_" & "s")
		$a_01_6 = {70 72 6f 67 72 65 73 73 5f 62 61 72 73 20 3d 20 52 65 70 6c 61 63 65 28 53 74 72 69 6e 67 28 34 2c 20 22 5a 22 29 2c 20 22 5a 22 2c 20 64 66 29 } //1 progress_bars = Replace(String(4, "Z"), "Z", df)
		$a_01_7 = {72 65 7a 7a 7a 75 6c 74 20 3d 20 72 65 7a 7a 7a 75 6c 74 20 26 20 62 6f 6f 6b 5f 72 65 62 6f 6f 6b 28 63 6f 6f 70 65 72 61 74 69 6f 6e 2c 20 75 29 20 26 } //1 rezzzult = rezzzult & book_rebook(cooperation, u) &
		$a_01_8 = {72 65 5f 6f 72 64 65 72 20 3d 20 53 68 65 65 74 73 28 31 29 2e 52 61 6e 67 65 28 22 42 31 3a 42 35 22 29 2e 53 70 65 63 69 61 6c 43 65 6c 6c 73 28 78 6c 43 65 6c 6c 54 79 70 65 43 6f 6e 73 74 61 6e 74 73 29 } //1 re_order = Sheets(1).Range("B1:B5").SpecialCells(xlCellTypeConstants)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}