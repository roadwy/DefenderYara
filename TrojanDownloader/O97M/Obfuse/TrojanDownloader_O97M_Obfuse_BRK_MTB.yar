
rule TrojanDownloader_O97M_Obfuse_BRK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BRK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 70 6c 69 74 28 73 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 29 2c 20 22 20 22 29 } //1 = Split(sr(ActiveDocument.BuiltInDocumentProperties("title")), " ")
		$a_01_1 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //1 frm.button1_Click
		$a_03_2 = {28 4c 65 6e 28 90 02 19 29 20 3c 20 31 30 32 34 29 20 54 68 65 6e 90 00 } //1
		$a_03_3 = {3d 20 4a 6f 69 6e 28 90 02 19 2c 20 22 22 29 90 00 } //1
		$a_01_4 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 } //1 = ActiveDocument.BuiltInDocumentProperties("title")
		$a_03_5 = {2e 65 78 65 63 20 28 73 72 28 90 02 19 29 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}