
rule TrojanDownloader_O97M_Donoff_CK{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CK,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f [0-50] 2f 90 0f 03 00 90 10 03 00 2e 6a 61 72 22 [0-0f] 20 3d 20 53 70 6c 69 74 28 55 52 4c 2c 20 22 2e 22 29 } //1
		$a_03_1 = {2e 52 75 6e 20 22 [0-2f] 5c 63 72 73 73 2e 6a 61 72 22 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_CK_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CK,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 0d 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 65 72 22 } //1 = "er"
		$a_01_1 = {3d 20 22 68 65 78 22 } //1 = "hex"
		$a_01_2 = {3d 20 22 74 43 6f 22 } //1 = "tCo"
		$a_01_3 = {3d 20 22 6e 74 72 22 } //1 = "ntr"
		$a_01_4 = {3d 20 22 70 74 43 22 } //1 = "ptC"
		$a_01_5 = {3d 20 22 6f 6e 74 22 } //1 = "ont"
		$a_01_6 = {3d 20 22 4a 53 63 22 } //1 = "JSc"
		$a_01_7 = {3d 20 22 72 69 70 22 } //1 = "rip"
		$a_01_8 = {3d 20 22 72 6f 6c 22 } //1 = "rol"
		$a_01_9 = {3d 20 22 2e 53 63 22 } //1 = ".Sc"
		$a_01_10 = {3d 20 22 63 72 69 22 } //1 = "cri"
		$a_01_11 = {3d 20 22 4d 53 53 22 } //1 = "MSS"
		$a_01_12 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74 20 3d 20 22 49 6e 74 65 72 6e 61 6c 20 45 72 72 6f 72 2e 20 50 6c 65 61 73 65 20 74 72 79 20 61 67 61 69 6e 2e 22 } //13 ActiveDocument.Content.Text = "Internal Error. Please try again."
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*13) >=21
 
}