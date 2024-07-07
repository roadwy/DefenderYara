
rule TrojanDownloader_O97M_Obfuse_IW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 78 73 6c 22 } //1 = "xsl"
		$a_03_1 = {43 61 6c 6c 20 90 02 09 28 90 02 08 28 22 74 65 6d 70 22 29 20 26 20 22 5c 90 00 } //1
		$a_03_2 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 90 02 10 2c 20 90 02 08 2c 20 32 29 29 29 90 00 } //1
		$a_03_3 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 10 29 20 53 74 65 70 20 32 90 00 } //1
		$a_01_4 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 63 63 65 70 74 41 6c 6c 52 65 76 69 73 69 6f 6e 73 53 68 6f 77 6e } //1 ActiveDocument.AcceptAllRevisionsShown
		$a_01_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 } //1 ActiveDocument.Bookmarks
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}