
rule TrojanDownloader_O97M_Obfuse_VPT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VPT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 63 20 28 73 72 28 74 6d 70 49 6e 64 65 78 29 29 } //1 .exec (sr(tmpIndex))
		$a_01_1 = {3d 20 4a 6f 69 6e 28 64 61 74 61 62 61 73 65 4c 6f 61 64 2c 20 22 22 29 } //1 = Join(databaseLoad, "")
		$a_01_2 = {3d 20 53 70 6c 69 74 28 73 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 29 2c 20 22 20 22 29 } //1 = Split(sr(ActiveDocument.BuiltInDocumentProperties("title")), " ")
		$a_03_3 = {28 4c 65 6e 28 [0-14] 29 20 3c 20 31 30 32 34 29 20 54 68 65 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_VPT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VPT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 63 20 28 73 72 28 72 69 67 68 74 42 75 74 74 6f 6e 29 29 } //1 .exec (sr(rightButton))
		$a_01_1 = {3d 20 4a 6f 69 6e 28 64 61 74 61 62 61 73 65 43 6f 75 6e 74 65 72 2c 20 22 22 29 } //1 = Join(databaseCounter, "")
		$a_01_2 = {3d 20 53 70 6c 69 74 28 73 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 29 2c 20 22 20 22 29 } //1 = Split(sr(ActiveDocument.BuiltInDocumentProperties("title")), " ")
		$a_03_3 = {28 4c 65 6e 28 [0-14] 29 20 3c 20 31 30 32 34 29 20 54 68 65 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_VPT_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VPT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 63 20 28 73 72 28 64 61 74 61 62 61 73 65 52 69 67 68 74 53 74 6f 72 61 67 65 29 29 } //1 .exec (sr(databaseRightStorage))
		$a_01_1 = {3d 20 4a 6f 69 6e 28 6d 65 6d 4c 69 73 74 62 6f 78 2c 20 22 22 29 } //1 = Join(memListbox, "")
		$a_01_2 = {3d 20 53 70 6c 69 74 28 73 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 29 2c 20 22 20 22 29 } //1 = Split(sr(ActiveDocument.BuiltInDocumentProperties("title")), " ")
		$a_03_3 = {28 4c 65 6e 28 [0-14] 29 20 3c 20 31 30 32 34 29 20 54 68 65 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_VPT_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VPT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 63 20 28 73 72 28 65 78 63 65 70 74 69 6f 6e 53 74 6f 72 61 67 65 4f 70 74 69 6f 6e 29 29 } //1 .exec (sr(exceptionStorageOption))
		$a_01_1 = {3d 20 4a 6f 69 6e 28 63 6f 75 6e 74 53 63 72 65 65 6e 54 69 74 6c 65 2c 20 22 22 29 } //1 = Join(countScreenTitle, "")
		$a_01_2 = {3d 20 53 70 6c 69 74 28 73 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 29 2c 20 22 20 22 29 } //1 = Split(sr(ActiveDocument.BuiltInDocumentProperties("title")), " ")
		$a_03_3 = {28 4c 65 6e 28 [0-14] 29 20 3c 20 31 30 32 34 29 20 54 68 65 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}