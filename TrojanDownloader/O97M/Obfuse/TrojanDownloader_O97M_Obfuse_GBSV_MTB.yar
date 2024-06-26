
rule TrojanDownloader_O97M_Obfuse_GBSV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GBSV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //01 00  = "bin.base64"
		$a_01_1 = {3d 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 } //01 00  = Chr$(Val("&H" & Mid$
		$a_03_2 = {28 22 53 45 74 46 57 56 39 44 56 56 4a 53 52 22 20 26 20 90 02 25 20 26 20 22 63 6d 39 7a 62 32 5a 30 58 45 39 6d 5a 6d 6c 6a 5a 56 77 3d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 90 00 } //01 00 
		$a_03_3 = {28 22 58 46 64 76 63 6d 52 63 55 32 22 20 26 20 90 02 25 20 26 20 22 6a 5a 58 4e 7a 56 6b 4a 50 54 51 3d 3d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 90 00 } //01 00 
		$a_03_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 22 20 26 20 90 02 25 20 26 20 22 65 6c 6c 22 29 90 0c 02 00 2e 52 65 67 57 72 69 74 65 20 90 02 25 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 90 0c 02 00 45 6e 64 20 57 69 74 68 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_5 = {2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 41 64 64 46 72 6f 6d 53 74 72 69 6e 67 } //01 00  .VBProject.VBComponents("ThisDocument").CodeModule.AddFromString
		$a_01_6 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 6f 72 64 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  = CreateObject("word.application")
		$a_01_7 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6d 73 78 6d 6c 32 2e 64 6f 6d 64 6f 63 75 6d 65 6e 74 22 29 } //01 00  = CreateObject("msxml2.domdocument")
		$a_01_8 = {2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 63 6f 64 65 22 29 } //00 00  .createElement("code")
	condition:
		any of ($a_*)
 
}