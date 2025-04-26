
rule TrojanDownloader_O97M_IcedID_RVO_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.RVO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-14] 2e 68 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-14] 20 3d 20 22 74 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-14] 20 3d 20 22 61 22 } //1
		$a_01_1 = {53 68 65 6c 6c 20 63 6f 6c 6c 65 63 74 69 6f 6e 43 75 72 72 65 6e 63 79 28 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 20 2f 63 20 22 29 } //1 Shell collectionCurrency("c:\windows\system32\cmd /c ")
		$a_01_2 = {63 75 72 42 6f 6f 6c 42 75 74 74 20 3d 20 22 21 22 } //1 curBoolButt = "!"
		$a_03_3 = {26 20 43 68 72 28 [0-14] 28 [0-14] 29 20 58 6f 72 20 31 31 30 29 } //1
		$a_01_4 = {6f 70 74 69 6f 6e 53 65 6c 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 29 } //1 optionSel(ActiveDocument.Content)
		$a_01_5 = {4f 70 65 6e 20 63 6f 6c 6c 65 63 74 69 6f 6e 43 75 72 72 65 6e 63 79 28 22 22 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 0d 0a 50 72 69 6e 74 20 23 31 2c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}