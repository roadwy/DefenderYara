
rule TrojanDownloader_O97M_IcedID_QNH_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.QNH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 61 51 4f 42 53 28 61 77 56 73 4a 65 20 41 73 20 56 61 72 69 61 6e 74 29 } //01 00  Function aQOBS(awVsJe As Variant)
		$a_01_1 = {61 78 6a 61 32 20 3d 20 22 22 } //01 00  axja2 = ""
		$a_01_2 = {61 30 46 57 4c 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 } //01 00  a0FWL = ActiveDocument.Content
		$a_03_3 = {53 68 65 6c 6c 20 61 31 74 35 6e 20 26 20 22 20 22 20 26 20 61 51 32 6e 48 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_4 = {20 3d 20 53 70 6c 69 74 28 61 76 33 35 78 2c } //01 00   = Split(av35x,
		$a_01_5 = {4f 70 65 6e 20 61 52 64 63 5a 4c 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //01 00  Open aRdcZL For Output As #1
		$a_01_6 = {50 72 69 6e 74 20 23 31 2c 20 61 57 72 61 79 67 } //00 00  Print #1, aWrayg
	condition:
		any of ($a_*)
 
}