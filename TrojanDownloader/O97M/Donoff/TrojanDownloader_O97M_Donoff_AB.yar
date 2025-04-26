
rule TrojanDownloader_O97M_Donoff_AB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 22 20 28 42 79 56 61 6c } //1 Lib "urlmon" Alias "URLDownloadToFileW" (ByVal
		$a_00_1 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 57 22 20 28 42 79 56 61 6c } //1 Lib "shell32.dll" Alias "ShellExecuteW" (ByVal
		$a_00_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 45 78 61 6d 70 6c 65 2e 65 78 65 22 } //1 = Environ("APPDATA") & "\Example.exe"
		$a_00_3 = {28 30 2c 20 53 74 72 50 74 72 28 22 4f 70 65 6e 22 29 2c } //1 (0, StrPtr("Open"),
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_AB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 65 6d 70 46 69 6c 65 20 3d 20 70 72 6f 63 65 73 73 45 6e 76 28 22 54 45 4d 50 22 29 20 2b 20 74 65 6d 70 46 69 6c 65 } //1 tempFile = processEnv("TEMP") + tempFile
		$a_01_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 74 65 6d 70 46 69 6c 65 2c 20 32 } //1 .savetofile tempFile, 2
		$a_01_2 = {74 65 6d 70 46 69 6c 65 20 3d 20 22 5c 22 20 2b 20 54 69 74 6c 65 20 2b 20 22 2e 65 78 65 22 } //1 tempFile = "\" + Title + ".exe"
		$a_01_3 = {68 74 74 70 52 65 71 75 65 73 74 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 63 6f 6d 70 75 74 65 72 2c 20 36 32 29 2c 20 46 61 6c 73 65 } //1 httpRequest.Open "GET", GetStringFromArray(computer, 62), False
		$a_01_4 = {72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 66 72 6f 6d 41 72 72 28 69 29 20 2d 20 4c 65 6e 4c 65 6e 20 2b 20 69 29 } //1 result = result & Chr(fromArr(i) - LenLen + i)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_AB_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 66 72 6f 6d 41 72 72 28 29 20 41 73 20 56 61 72 69 61 6e 74 2c 20 4c 65 6e 4c 65 6e 20 41 73 20 49 6e 74 65 67 65 72 29 20 41 73 20 53 74 72 69 6e 67 } //1 GetStringFromArray(fromArr() As Variant, LenLen As Integer) As String
		$a_01_1 = {72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 66 72 6f 6d 41 72 72 28 69 29 20 2d 20 4c 65 6e 4c 65 6e 20 2b 20 69 20 2a 20 32 29 } //1 result = result & Chr(fromArr(i) - LenLen + i * 2)
		$a_01_2 = {63 6f 6d 70 75 74 65 72 20 3d 20 41 72 72 61 79 28 31 34 34 2c 20 31 35 34 2c 20 31 35 32 2c 20 31 34 36 2c 20 39 30 2c 20 37 37 2c 20 37 35 2c } //1 computer = Array(144, 154, 152, 146, 90, 77, 75,
		$a_01_3 = {68 74 74 70 52 65 71 75 65 73 74 2e 4f 70 65 6e 20 22 47 45 22 20 2b 20 22 54 22 2c 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 63 6f 6d 70 75 74 65 72 2c 20 34 30 29 2c 20 46 61 6c 73 65 } //1 httpRequest.Open "GE" + "T", GetStringFromArray(computer, 40), False
		$a_01_4 = {73 68 65 6c 6c 41 70 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 22 20 2b 20 22 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 shellApp = CreateObject("She" + "ll.Application")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}