
rule TrojanDownloader_O97M_EncDoc_OKM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.OKM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 } //1 Sub auto_open()
		$a_01_1 = {44 69 6d 20 73 74 72 4d 61 63 72 6f 20 41 73 20 53 74 72 69 6e 67 } //1 Dim strMacro As String
		$a_01_2 = {53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 44 31 32 32 22 29 2e 4e 61 6d 65 20 3d 20 22 6f 6b 22 } //1 Sheets("Macro1").Range("D122").Name = "ok"
		$a_01_3 = {53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 44 31 33 30 22 29 20 3d 20 22 3d 45 58 45 43 28 22 20 2b 20 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 44 31 33 35 22 29 2e 56 61 6c 75 65 } //1 Sheets("Macro1").Range("D130") = "=EXEC(" + Sheets("Macro1").Range("D135").Value
		$a_01_4 = {73 74 72 4d 61 63 72 6f 20 3d 20 22 6f 6b 22 } //1 strMacro = "ok"
		$a_01_5 = {52 75 6e 20 28 73 74 72 4d 61 63 72 6f 29 } //1 Run (strMacro)
		$a_01_6 = {53 65 74 20 45 78 63 65 6c 53 68 65 65 74 20 3d 20 4e 6f 74 68 69 6e 67 } //1 Set ExcelSheet = Nothing
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}