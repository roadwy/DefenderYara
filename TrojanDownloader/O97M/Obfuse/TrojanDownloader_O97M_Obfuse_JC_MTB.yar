
rule TrojanDownloader_O97M_Obfuse_JC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 61 6e 61 6e 61 61 72 65 73 74 73 69 67 69 72 69 79 61 2e 63 6f 6d 2f 79 74 70 71 61 78 77 71 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } //01 00  http://bananaarestsigiriya.com/ytpqaxwq/555555555.png
		$a_01_1 = {43 3a 5c 46 65 74 69 6c 5c 47 69 6f 6c 61 5c 6f 63 65 61 6e 44 68 } //00 00  C:\Fetil\Giola\oceanDh
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JC_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 78 73 6c 22 } //01 00  = "xsl"
		$a_01_1 = {28 22 74 65 6d 70 22 29 } //01 00  ("temp")
		$a_03_2 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 90 02 10 2c 20 90 02 08 2c 20 32 29 29 29 90 00 } //01 00 
		$a_03_3 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 10 29 20 53 74 65 70 20 32 90 00 } //01 00 
		$a_01_4 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 63 63 65 70 74 41 6c 6c 52 65 76 69 73 69 6f 6e 73 53 68 6f 77 6e } //01 00  ActiveDocument.AcceptAllRevisionsShown
		$a_01_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 } //00 00  ActiveDocument.Bookmarks
	condition:
		any of ($a_*)
 
}