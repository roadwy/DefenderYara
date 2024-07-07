
rule TrojanDownloader_O97M_Qakbot_DAE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.DAE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c 20 70 43 61 6c 6c 65 72 20 41 73 20 4c 6f 6e 67 2c 20 5f } //1 Alias "URLDownloadToFileA" (ByVal pCaller As Long, _
		$a_01_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 74 72 65 73 28 29 } //1 Public Function tres()
		$a_01_2 = {44 69 70 6f 64 65 20 3d 20 22 68 74 74 70 3a 2f 2f 22 } //1 Dipode = "http://"
		$a_03_3 = {47 75 69 6b 67 68 6a 67 66 68 20 3d 20 90 02 08 20 26 20 53 68 65 65 74 73 28 22 46 69 6c 65 73 22 29 2e 52 61 6e 67 65 28 22 42 36 30 22 29 90 00 } //1
		$a_01_4 = {42 74 64 75 66 6a 6b 68 6e 20 3d 20 53 68 65 65 74 73 28 22 46 69 6c 65 73 22 29 2e 52 61 6e 67 65 28 22 42 35 36 22 29 } //1 Btdufjkhn = Sheets("Files").Range("B56")
		$a_03_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 47 75 69 6b 67 68 6a 67 66 68 2c 20 42 74 64 75 66 6a 6b 68 6e 2c 20 30 2c 20 30 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}