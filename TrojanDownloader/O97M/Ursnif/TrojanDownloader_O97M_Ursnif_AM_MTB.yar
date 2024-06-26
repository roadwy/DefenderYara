
rule TrojanDownloader_O97M_Ursnif_AM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 31 33 20 2b 20 32 20 2b 20 35 30 20 2b 20 34 39 20 2b 20 31 29 20 2b 20 22 68 65 6c 6c 22 } //01 00  = Chr(13 + 2 + 50 + 49 + 1) + "hell"
		$a_01_1 = {2e 43 6f 6e 74 72 6f 6c 73 28 4c 65 6e 28 22 61 22 29 29 2e 56 61 6c 75 65 } //01 00  .Controls(Len("a")).Value
		$a_03_2 = {4f 70 65 6e 20 54 72 69 6d 28 90 02 50 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_03_3 = {50 72 69 6e 74 20 23 90 01 01 2c 20 90 02 50 2e 54 65 78 74 90 00 } //01 00 
		$a_01_4 = {43 6c 6f 73 65 20 23 } //01 00  Close #
		$a_01_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00  Sub AutoOpen()
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Ursnif_AM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 20 22 5c 90 02 10 2e 78 22 90 00 } //01 00 
		$a_03_1 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 90 02 08 2c 20 90 02 06 2c 20 90 02 06 29 29 90 00 } //01 00 
		$a_01_2 = {3d 20 22 74 6d 70 22 } //01 00  = "tmp"
		$a_03_3 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 08 28 29 20 90 02 10 2c 20 31 29 90 00 } //01 00 
		$a_01_4 = {3d 20 22 22 } //01 00  = ""
		$a_01_5 = {28 22 77 69 6e 6d 67 6d 74 73 3a 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //01 00  ("winmgmts:root\cimv2:Win32_Process")
		$a_03_6 = {3d 20 45 6e 76 69 72 6f 6e 28 90 02 10 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}