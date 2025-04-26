
rule TrojanDownloader_O97M_Obfuse_PAX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 72 69 76 61 74 65 20 61 28 [0-06] 29 20 41 73 20 56 61 72 69 61 6e 74 } //1
		$a_01_1 = {3d 20 46 72 65 65 46 69 6c 65 } //1 = FreeFile
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 74 65 73 74 5f 6d 61 6b 65 5f 64 6f 63 2e 65 78 65 } //1 = Environ("TMP") & "\test_make_doc.exe
		$a_03_3 = {3d 20 53 68 65 6c 6c 28 [0-15] 2c 20 31 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_PAX_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 31 2e 64 6f 74 } //1 Open "C:\Users\Public\Documents\1.dot
		$a_01_1 = {53 65 74 20 72 6f 6f 74 46 6f 6c 64 65 72 20 3d 20 73 65 72 76 69 63 65 2e 47 65 74 46 6f 6c 64 65 72 28 22 5c 22 29 } //1 Set rootFolder = service.GetFolder("\")
		$a_03_2 = {3d 20 4d 69 64 24 28 [0-0f] 2c 20 58 2c 20 31 29 } //1
		$a_01_3 = {3d 20 56 61 6c 75 65 20 2b 20 43 68 72 28 56 61 6c 28 22 26 68 22 20 26 20 6e 75 6d 29 29 } //1 = Value + Chr(Val("&h" & num))
		$a_03_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 48 32 41 28 48 32 41 28 41 72 72 61 79 4c 69 73 74 28 [0-04] 29 } //1
		$a_01_5 = {43 61 6c 6c 20 73 65 72 76 69 63 65 2e 43 6f 6e 6e 65 63 74 } //1 Call service.Connect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}