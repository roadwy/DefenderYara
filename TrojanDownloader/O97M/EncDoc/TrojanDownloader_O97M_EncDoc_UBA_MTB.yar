
rule TrojanDownloader_O97M_EncDoc_UBA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.UBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 65 6d 6d 69 6f 70 20 3d 20 64 7a 7a 69 20 26 20 22 52 22 20 26 20 22 49 22 } //1 hemmiop = dzzi & "R" & "I"
		$a_01_1 = {53 77 20 3d 20 34 3a 20 53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 31 37 2c 20 31 29 2e 46 6f 72 6d 75 6c 61 4c 6f 63 61 6c 20 3d 20 68 65 6d 6d 69 6f 70 20 26 20 64 61 42 42 } //1 Sw = 4: Sheets(1).Cells(17, 1).FormulaLocal = hemmiop & daBB
		$a_01_2 = {64 61 42 42 20 3d 20 22 54 22 20 26 20 73 77 65 6c 6c 73 20 26 20 22 4f 22 20 26 20 22 28 29 22 } //1 daBB = "T" & swells & "O" & "()"
		$a_01_3 = {53 68 65 65 74 73 28 31 29 2e 5b 41 35 5d 2e 46 6f 72 6d 75 6c 61 4c 6f 63 61 6c 20 3d 20 71 71 } //1 Sheets(1).[A5].FormulaLocal = qq
		$a_01_4 = {64 7a 7a 69 20 3d 20 22 63 22 3a 20 64 7a 7a 69 20 3d 20 22 3d 22 } //1 dzzi = "c": dzzi = "="
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}