
rule TrojanDownloader_O97M_Qakbot_DST_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.DST!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {23 49 66 20 56 42 41 37 20 54 68 65 6e 90 0c 02 00 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 5f } //1
		$a_01_1 = {41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c 20 70 43 61 6c 6c 65 72 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 73 7a 55 52 4c 20 41 73 20 53 74 72 69 6e 67 2c 20 5f } //1 Alias "URLDownloadToFileA" (ByVal pCaller As Long, ByVal szURL As String, _
		$a_01_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 44 61 73 65 72 74 28 29 } //1 Public Function Dasert()
		$a_01_3 = {69 6d 67 73 72 63 20 3d 20 22 68 74 74 70 3a 2f 2f 22 20 26 20 53 68 65 65 74 73 28 22 44 6f 63 73 22 29 2e 52 61 6e 67 65 28 22 41 33 35 22 29 } //1 imgsrc = "http://" & Sheets("Docs").Range("A35")
		$a_01_4 = {64 6c 70 61 74 68 20 3d 20 53 68 65 65 74 73 28 22 44 6f 63 73 22 29 2e 52 61 6e 67 65 28 22 52 32 22 29 } //1 dlpath = Sheets("Docs").Range("R2")
		$a_03_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 69 6d 67 73 72 63 2c 20 64 6c 70 61 74 68 2c 20 30 2c 20 30 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}