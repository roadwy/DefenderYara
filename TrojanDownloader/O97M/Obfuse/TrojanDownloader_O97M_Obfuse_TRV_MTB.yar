
rule TrojanDownloader_O97M_Obfuse_TRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.TRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 22 65 78 70 6c 6f 72 65 72 20 [0-0f] 2e 68 74 61 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //1
		$a_03_1 = {4f 70 65 6e 20 22 [0-0f] 2e 68 74 61 22 20 26 20 62 75 74 74 6f 6e 52 65 66 65 72 65 6e 63 65 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } //1
		$a_01_2 = {50 72 69 6e 74 20 23 31 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 } //1 Print #1, ActiveDocument.Range.Text
		$a_01_3 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_TRV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.TRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 52 65 70 6c 61 63 65 28 22 77 73 63 72 69 70 74 20 22 22 46 49 4c 45 22 22 20 22 2c 20 22 46 49 4c 45 22 2c 20 6d 79 46 69 6c 65 29 } //1 Shell Replace("wscript ""FILE"" ", "FILE", myFile)
		$a_03_1 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 22 22 22 22 22 22 25 55 73 65 72 50 72 6f 66 69 6c 65 25 5c [0-0a] 2e 65 78 65 22 22 22 22 20 2d 64 } //1
		$a_03_2 = {6d 79 46 69 6c 65 20 3d 20 75 73 65 72 50 72 6f 66 69 6c 65 50 61 74 68 20 2b 20 22 5c 6c 61 79 6f 66 66 73 [0-02] 2e 76 62 73 22 } //1
		$a_01_3 = {4f 70 65 6e 20 6d 79 46 69 6c 65 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 6d 79 6f 75 74 70 75 74 66 69 6c 65 } //1 Open myFile For Output As #myoutputfile
		$a_01_4 = {50 72 69 6e 74 20 23 6d 79 6f 75 74 70 75 74 66 69 6c 65 2c 20 22 48 54 54 50 44 6f 77 6e 6c 6f 61 64 20 22 22 68 74 74 70 3a 2f 2f } //1 Print #myoutputfile, "HTTPDownload ""http://
		$a_01_5 = {6f 62 6a 46 69 6c 65 2e 57 72 69 74 65 20 43 68 72 28 41 73 63 42 28 4d 69 64 42 28 6f 62 6a 48 54 54 50 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 2c 20 69 2c 20 31 29 29 29 } //1 objFile.Write Chr(AscB(MidB(objHTTP.ResponseBody, i, 1)))
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}