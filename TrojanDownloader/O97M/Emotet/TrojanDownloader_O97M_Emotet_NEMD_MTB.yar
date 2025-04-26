
rule TrojanDownloader_O97M_Emotet_NEMD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.NEMD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 46 69 6c 65 51 75 65 72 79 52 61 6e 67 65 28 42 79 56 61 6c 20 66 69 6c 65 6e 61 6d 65 24 2c 20 4f 70 74 69 6f 6e 61 6c 20 42 79 56 61 6c 20 54 61 62 6c 65 73 24 29 20 41 73 20 52 61 6e 67 65 } //1 Function FileQueryRange(ByVal filename$, Optional ByVal Tables$) As Range
		$a_01_1 = {44 69 6d 20 74 6d 70 53 68 65 65 74 20 41 73 20 57 6f 72 6b 73 68 65 65 74 3a 20 53 65 74 20 74 6d 70 53 68 65 65 74 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 29 } //1 Dim tmpSheet As Worksheet: Set tmpSheet = ThisWorkbook.Worksheets(")
		$a_03_2 = {72 61 20 3d 20 52 65 70 6c 61 63 65 28 73 32 2c 20 22 [0-10] 22 2c 20 22 22 29 } //1
		$a_01_3 = {74 78 74 24 20 3d 20 46 69 6c 65 54 6f 56 42 41 46 75 6e 63 74 69 6f 6e 28 22 2c 22 2c 20 22 2c 22 29 } //1 txt$ = FileToVBAFunction(",", ",")
		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 22 20 2b 20 73 31 20 2b 20 22 72 69 70 74 2e 53 68 65 22 20 26 20 22 6c 6c 22 29 } //1 = CreateObject("Wsc" + s1 + "ript.She" & "ll")
		$a_01_5 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 74 78 74 24 29 } //1 For i = 1 To Len(txt$)
		$a_01_6 = {66 69 6c 65 6e 61 6d 65 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 47 65 74 4f 70 65 6e 46 69 6c 65 6e 61 6d 65 28 22 2c 22 2c 20 2c 20 22 2c 22 2c 20 22 2e 22 29 } //1 filename = Application.GetOpenFilename(",", , ",", ".")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}