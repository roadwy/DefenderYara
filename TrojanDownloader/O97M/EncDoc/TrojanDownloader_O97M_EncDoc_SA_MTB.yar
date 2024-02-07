
rule TrojanDownloader_O97M_EncDoc_SA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //01 00  Sub Workbook_Open()
		$a_01_1 = {3d 20 52 61 6e 67 65 28 22 41 31 3a 41 31 33 22 29 } //01 00  = Range("A1:A13")
		$a_01_2 = {3d 20 6d 79 52 61 6e 67 65 2e 43 6f 75 6e 74 } //01 00  = myRange.Count
		$a_01_3 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 74 65 78 74 66 69 6c 65 2e 77 73 66 22 } //01 00  = "C:\Users\Public\textfile.wsf"
		$a_01_4 = {3d 20 22 77 73 63 72 69 70 74 20 22 20 2b 20 6d 79 46 69 6c 65 } //01 00  = "wscript " + myFile
		$a_01_5 = {53 68 65 6c 6c 20 6b 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //00 00  Shell k, vbNormalFocus
	condition:
		any of ($a_*)
 
}