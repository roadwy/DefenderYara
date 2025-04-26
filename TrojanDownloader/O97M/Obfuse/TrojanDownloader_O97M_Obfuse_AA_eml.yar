
rule TrojanDownloader_O97M_Obfuse_AA_eml{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AA!eml,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_1 = {52 65 70 6c 61 63 65 28 22 ?? 22 2c 20 22 [0-0f] 22 2c 20 22 22 } //1
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 65 6c 65 63 74 69 6f 6e 2e 49 6e 73 65 72 74 4e 65 77 50 61 67 65 } //1 Application.Selection.InsertNewPage
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 28 29 20 41 73 20 4c 6f 6e 67 } //1 GetTickCount Lib "kernel32" () As Long
		$a_01_4 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 63 74 69 76 65 57 69 6e 64 6f 77 2e 56 69 65 77 2e 44 69 73 70 6c 61 79 42 61 63 6b 67 72 6f 75 6e 64 73 20 3d 20 46 61 6c 73 65 } //1 ActiveDocument.ActiveWindow.View.DisplayBackgrounds = False
		$a_01_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 44 65 6c 65 74 65 } //1 ActiveDocument.Range.Delete
		$a_01_6 = {58 6f 72 20 4c 65 6e 28 } //1 Xor Len(
		$a_01_7 = {4f 72 20 56 61 6c 28 22 20 } //1 Or Val(" 
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}