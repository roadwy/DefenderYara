
rule TrojanDownloader_O97M_Obfuse_GBSE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GBSE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 61 6d 65 73 70 61 63 65 47 6c 6f 62 61 6c 52 65 71 75 65 73 74 2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 namespaceGlobalRequest.DataType = "bin.base64"
		$a_01_1 = {3d 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 74 72 75 73 74 54 65 78 74 62 6f 78 50 74 72 2c 20 71 75 65 72 79 51 75 65 72 79 54 65 78 74 2c 20 32 29 29 29 } //1 = Chr$(Val("&H" & Mid$(trustTextboxPtr, queryQueryText, 2)))
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65 20 61 72 67 75 6d 65 6e 74 4c 69 6e 6b 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 } //1 CreateObject("wscript.shell").RegWrite argumentLink, 1, "REG_DWORD"
		$a_01_3 = {3d 20 53 74 72 43 6f 6e 76 28 62 75 66 66 65 72 44 61 74 61 28 22 53 45 74 46 57 56 39 44 56 56 4a 53 52 55 35 55 58 31 56 54 52 56 4a 63 55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 45 39 6d 5a 6d 6c 6a 5a 56 77 3d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 } //1 = StrConv(bufferData("SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XE9mZmljZVw="), vbUnicode)
		$a_01_4 = {72 65 6d 6f 76 65 54 61 62 6c 65 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 41 64 64 46 72 6f 6d 53 74 72 69 6e 67 20 6c 69 73 74 62 6f 78 53 74 6f 72 61 67 65 43 6f 75 6e 74 65 72 } //1 removeTable.VBProject.VBComponents("ThisDocument").CodeModule.AddFromString listboxStorageCounter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}