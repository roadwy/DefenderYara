
rule TrojanDownloader_O97M_Donoff_BSB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BSB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 56 69 65 77 43 6c 6f 73 65 41 6c 6c 28 29 } //1 Sub ViewCloseAll()
		$a_03_1 = {3d 20 46 53 4f 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 26 20 22 5c 32 30 31 39 [0-07] 2e 64 6f 63 22 } //1
		$a_01_2 = {6f 62 6a 57 69 6e 48 74 74 70 2e 73 65 6e 64 20 22 22 } //1 objWinHttp.send ""
		$a_01_3 = {3d 20 34 31 39 38 20 54 68 65 6e 20 4d 73 67 42 6f 78 20 22 44 6f 63 75 6d 65 6e 74 20 77 61 73 20 6e 6f 74 20 63 6c 6f 73 65 64 22 } //1 = 4198 Then MsgBox "Document was not closed"
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}