
rule TrojanDownloader_O97M_Donoff_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 74 65 6d 70 2e 64 6f 63 22 29 } //1 .Open("C:\Users\Public\Documents\temp.doc")
		$a_01_1 = {6f 62 6a 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 73 74 72 55 72 6c 2c 20 46 61 6c 73 65 } //1 objHttp.Open "GET", strUrl, False
		$a_01_2 = {73 74 72 55 72 6c 20 26 20 43 68 72 28 34 37 29 20 26 20 22 6f 72 64 30 33 22 20 26 20 43 68 72 28 34 37 29 20 26 20 73 74 72 53 72 63 46 69 6c 65 4e 61 6d 65 } //1 strUrl & Chr(47) & "ord03" & Chr(47) & strSrcFileName
		$a_01_3 = {41 73 63 42 28 4d 69 64 42 28 6f 62 6a 48 74 74 70 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 2c 20 69 20 2b 20 31 2c 20 31 29 29 } //1 AscB(MidB(objHttp.ResponseBody, i + 1, 1))
		$a_01_4 = {45 72 72 20 3d 20 34 31 39 38 20 54 68 65 6e 20 4d 73 67 42 6f 78 20 22 44 6f 63 75 6d 65 6e 74 20 77 61 73 20 6e 6f 74 20 63 6c 6f 73 65 64 22 } //1 Err = 4198 Then MsgBox "Document was not closed"
		$a_01_5 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Document_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}