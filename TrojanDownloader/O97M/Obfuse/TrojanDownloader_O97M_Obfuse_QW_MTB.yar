
rule TrojanDownloader_O97M_Obfuse_QW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 20 43 68 72 28 56 61 6c 28 90 02 06 28 22 90 02 04 22 29 20 26 90 00 } //01 00 
		$a_03_1 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 25 29 90 00 } //01 00 
		$a_01_2 = {26 20 22 34 62 } //01 00  & "4b
		$a_01_3 = {26 20 22 35 } //01 00  & "5
		$a_01_4 = {26 20 22 37 } //01 00  & "7
		$a_01_5 = {33 33 33 34 33 33 } //01 00  333433
		$a_01_6 = {3d 20 49 73 4e 75 6c 6c 28 22 22 29 } //01 00  = IsNull("")
		$a_01_7 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //00 00  = "1Normal.ThisDocument"
	condition:
		any of ($a_*)
 
}