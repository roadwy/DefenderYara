
rule TrojanDownloader_O97M_EncDoc_ERV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ERV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 56 69 75 72 6e 69 28 29 } //1 Public Function Viurni()
		$a_01_1 = {26 20 53 68 65 65 74 73 28 22 44 6f 63 73 31 22 29 2e 52 61 6e 67 65 28 22 42 33 30 22 29 } //1 & Sheets("Docs1").Range("B30")
		$a_01_2 = {3d 20 53 68 65 65 74 73 28 22 44 6f 63 73 32 22 29 2e 52 61 6e 67 65 28 22 4c 31 37 22 29 } //1 = Sheets("Docs2").Range("L17")
		$a_01_3 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 5f } //1 Private Declare Function URLDownloadToFile Lib "urlmon" _
		$a_03_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 76 6e 64 68 2c 20 64 6c 70 61 74 68 2c 20 30 2c 20 30 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_03_5 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e [0-08] 23 45 6c 73 65 [0-07] 23 45 6e 64 20 49 66 90 0c 02 00 23 45 6c 73 65 90 0c 02 00 23 45 6e 64 20 49 66 } //1
		$a_01_6 = {41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c 20 70 43 61 6c 6c 65 72 20 41 73 20 4c 6f 6e 67 2c 20 5f } //1 Alias "URLDownloadToFileA" (ByVal pCaller As Long, _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}