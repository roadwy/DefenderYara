
rule TrojanDownloader_O97M_Obfuse_HC{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HC,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 42 6f 78 20 22 76 64 66 67 68 65 66 64 67 66 67 22 } //1 MsgBox "vdfghefdgfg"
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 4f 66 66 69 63 65 57 6f 72 64 2e 65 78 65 22 } //1 = Environ("temp") & "\MicrosoftOfficeWord.exe"
		$a_01_2 = {67 65 74 55 72 6c 33 20 3d 20 22 68 74 74 70 3a 2f 2f 35 34 2e 33 39 2e 31 34 34 2e 32 35 30 2f 22 } //1 getUrl3 = "http://54.39.144.250/"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}