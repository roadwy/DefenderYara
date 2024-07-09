
rule TrojanDownloader_O97M_Obfuse_MQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_1 = {64 77 52 65 73 65 72 76 65 64 } //1 dwReserved
		$a_03_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 [0-0a] 2c 20 [0-0a] 2c 20 30 2c 20 30 } //1
		$a_01_3 = {53 68 65 65 74 73 28 47 65 72 74 29 2e 52 61 6e 67 65 28 42 79 79 74 75 69 74 79 29 } //1 Sheets(Gert).Range(Byytuity)
		$a_01_4 = {53 68 65 65 74 73 28 22 46 69 6c 65 73 22 29 2e 52 61 6e 67 65 28 22 42 36 30 22 29 } //1 Sheets("Files").Range("B60")
		$a_01_5 = {68 74 74 70 3a 2f 2f } //1 http://
		$a_01_6 = {49 66 20 56 42 41 37 20 54 68 65 6e } //1 If VBA7 Then
		$a_01_7 = {49 66 20 57 69 6e 36 34 20 54 68 65 6e } //1 If Win64 Then
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Obfuse_MQ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e } //1 #If Win64 Then
		$a_01_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 53 68 76 74 45 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 57 22 20 28 42 79 56 61 6c 20 78 4c 58 47 6f 20 41 73 20 4c 6f 6e 67 50 74 72 2c } //1 Private Declare PtrSafe Function ShvtE Lib "shell32" Alias "ShellExecuteW" (ByVal xLXGo As LongPtr,
		$a_01_2 = {43 61 6c 6c 20 53 68 76 74 45 28 30 2c 20 53 74 72 50 74 72 28 22 6f 50 65 4e 22 29 2c 20 53 74 72 50 74 72 28 53 70 6c 69 74 28 5a 66 64 62 73 64 72 67 73 72 65 67 2e 55 6e 73 6a 6b 66 73 65 38 34 35 38 33 37 35 34 2e 54 61 67 2c } //1 Call ShvtE(0, StrPtr("oPeN"), StrPtr(Split(Zfdbsdrgsreg.Unsjkfse84583754.Tag,
		$a_01_3 = {2e 54 61 67 2c 20 43 68 72 57 24 28 33 32 29 29 28 30 29 29 29 29 2c 20 53 74 72 50 74 72 28 22 22 29 2c 20 31 29 } //1 .Tag, ChrW$(32))(0)))), StrPtr(""), 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}