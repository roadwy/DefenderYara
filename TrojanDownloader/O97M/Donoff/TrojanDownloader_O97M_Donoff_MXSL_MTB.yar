
rule TrojanDownloader_O97M_Donoff_MXSL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXSL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 64 6f 63 75 6d 65 6e 74 49 6e 64 65 78 50 72 6f 63 22 } //01 00  Attribute VB_Name = "documentIndexProc"
		$a_01_1 = {64 61 74 61 4f 70 74 69 6f 6e 4c 6f 63 61 6c 28 22 53 45 74 46 57 56 39 44 56 56 4a 53 52 55 35 55 58 31 56 54 52 56 4a 63 55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 45 39 6d 5a 6d 6c 6a 5a 56 77 3d 22 29 } //01 00  dataOptionLocal("SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XE9mZmljZVw=")
		$a_01_2 = {64 61 74 61 4f 70 74 69 6f 6e 4c 6f 63 61 6c 28 22 58 46 64 76 63 6d 52 63 55 32 56 6a 64 58 4a 70 64 48 6c 63 51 57 4e 6a 5a 58 4e 7a 56 6b 4a 50 54 51 3d 3d 22 29 } //01 00  dataOptionLocal("XFdvcmRcU2VjdXJpdHlcQWNjZXNzVkJPTQ==")
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65 } //01 00  CreateObject("wscript.shell").RegWrite
		$a_01_4 = {76 61 6c 75 65 44 6f 63 75 6d 65 6e 74 43 6f 6e 76 65 72 74 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 } //01 00  valueDocumentConvert = UserForm1.TextBox1
		$a_01_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6d 73 78 6d 6c 32 2e 64 6f 6d 64 6f 63 75 6d 65 6e 74 22 29 } //01 00  CreateObject("msxml2.domdocument")
		$a_01_6 = {44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //01 00  DataType = "bin.base64"
		$a_01_7 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 6f 72 64 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //00 00  CreateObject("word.application")
	condition:
		any of ($a_*)
 
}