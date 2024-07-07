
rule TrojanDownloader_O97M_EncDoc_UBB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.UBB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 78 63 65 6c 34 4d 61 63 72 6f 53 68 65 65 74 73 2e 41 64 64 20 42 65 66 6f 72 65 3a 3d 57 6f 72 6b 73 68 65 65 74 73 28 31 29 3a 20 41 63 74 69 76 65 53 68 65 65 74 2e 56 69 73 69 62 6c 65 20 3d 20 78 6c 53 68 65 65 74 48 69 64 64 65 6e } //1 Excel4MacroSheets.Add Before:=Worksheets(1): ActiveSheet.Visible = xlSheetHidden
		$a_01_1 = {73 77 65 6c 6c 73 20 3d 20 68 5f 74 65 73 74 6f 20 26 20 22 52 4e 22 } //1 swells = h_testo & "RN"
		$a_01_2 = {6e 69 6f 20 3d 20 6b 6f 3a 20 52 75 6e 20 28 22 22 20 26 20 22 41 22 20 26 20 33 29 } //1 nio = ko: Run ("" & "A" & 3)
		$a_01_3 = {73 6f 6c 6f 55 6e 69 6f 20 3d 20 53 70 6c 69 74 28 54 6b 2c 20 22 6b 22 29 } //1 soloUnio = Split(Tk, "k")
		$a_01_4 = {62 69 63 6f 20 3d 20 28 6e 69 6b 6f 6c 4c 28 64 7a 7a 69 20 26 20 76 69 2c 20 31 20 2b 20 6a 69 6f 29 29 3a 20 70 69 63 6f 6e 6f 73 20 28 31 31 32 29 } //1 bico = (nikolL(dzzi & vi, 1 + jio)): piconos (112)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}