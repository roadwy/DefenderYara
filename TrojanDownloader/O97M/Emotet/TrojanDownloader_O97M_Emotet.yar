
rule TrojanDownloader_O97M_Emotet{
	meta:
		description = "TrojanDownloader:O97M/Emotet,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 90 02 10 22 0d 0a 53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 00 } //1
		$a_01_1 = {2c 20 49 4e 4b 45 44 4c 69 62 2c 20 49 6e 6b 45 64 69 74 22 } //1 , INKEDLib, InkEdit"
		$a_01_2 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 36 20 3c 20 33 } //1 .ShowWindow = 6 < 3
		$a_01_3 = {22 29 29 2e 43 72 65 61 74 65 28 } //1 ")).Create(
		$a_01_4 = {2e 42 6f 6f 6b 6d 61 72 6b 73 28 22 5c 50 61 67 65 22 29 2e 52 61 6e 67 65 2e 44 65 6c 65 74 65 } //1 .Bookmarks("\Page").Range.Delete
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}