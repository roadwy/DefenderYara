
rule TrojanDownloader_O97M_Obfuse_RVBC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,10 00 10 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 90 02 19 28 22 90 02 19 22 29 29 2e 56 61 6c 75 65 90 00 } //03 00 
		$a_03_1 = {4d 69 64 28 90 02 28 2c 20 90 02 28 20 2b 20 31 2c 20 31 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //03 00 
		$a_03_2 = {47 65 74 4f 62 6a 65 63 74 28 90 02 19 28 22 90 02 19 22 29 29 90 00 } //03 00 
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 73 74 72 49 6e 70 75 74 29 29 } //01 00  StrReverse(ActiveDocument.CustomDocumentProperties(strInput))
		$a_01_4 = {3d 20 54 69 6d 65 72 28 29 20 2b 20 28 46 69 6e 69 73 68 29 } //01 00  = Timer() + (Finish)
		$a_01_5 = {3d 20 54 69 6d 65 72 28 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //03 00 
		$a_01_6 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //00 00  Sub Document_Open()
	condition:
		any of ($a_*)
 
}