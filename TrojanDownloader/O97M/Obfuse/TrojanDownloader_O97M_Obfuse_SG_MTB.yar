
rule TrojanDownloader_O97M_Obfuse_SG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 61 73 20 3d 20 52 65 70 6c 61 63 65 28 22 6d 90 17 03 04 04 03 44 61 74 61 43 6f 64 65 4e 65 74 90 00 } //1
		$a_03_1 = {64 61 73 20 3d 20 52 65 70 6c 61 63 65 28 22 53 79 73 74 65 6d 90 02 70 2e 65 78 65 53 79 73 74 65 6d 90 02 2e 22 2c 20 22 53 79 73 74 65 6d 90 1b 01 22 2c 20 22 22 29 90 00 } //1
		$a_03_2 = {28 30 2c 20 64 61 73 2c 20 73 61 73 2c 20 30 2c 20 30 29 90 02 03 49 66 20 72 65 74 20 3d 20 30 20 54 68 65 6e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_SG_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 } //1 'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox
		$a_01_1 = {46 6f 72 20 45 61 63 68 20 70 20 49 6e 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 42 75 69 6c 74 69 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 } //1 For Each p In ActiveWorkbook.BuiltinDocumentProperties
		$a_03_2 = {53 65 74 20 6f 50 72 6f 63 65 73 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 65 6c 6c 73 28 90 02 02 2c 20 90 02 02 29 29 90 00 } //1
		$a_01_3 = {41 74 28 70 2e 56 61 6c 75 65 29 } //1 At(p.Value)
		$a_01_4 = {57 6f 72 6b 73 68 65 65 74 73 28 31 29 2e 41 63 74 69 76 61 74 65 } //1 Worksheets(1).Activate
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}