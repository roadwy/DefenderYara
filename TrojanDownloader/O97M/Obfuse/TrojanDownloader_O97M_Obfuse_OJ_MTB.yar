
rule TrojanDownloader_O97M_Obfuse_OJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.OJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 6c 50 79 72 61 6d 69 64 42 61 72 53 74 61 63 6b 65 64 31 30 30 } //01 00  xlPyramidBarStacked100
		$a_01_1 = {43 68 72 57 28 43 4c 6e 67 28 28 30 2e 32 38 33 30 31 38 38 36 37 39 32 34 35 32 38 20 2a 20 33 37 31 29 } //01 00  ChrW(CLng((0.283018867924528 * 371)
		$a_01_2 = {78 6c 44 69 61 6c 6f 67 53 65 74 42 61 63 6b 67 72 6f 75 6e 64 50 69 63 74 75 72 65 20 2d 20 35 31 30 2e 31 37 31 37 31 37 31 37 31 37 31 37 } //01 00  xlDialogSetBackgroundPicture - 510.171717171717
		$a_01_3 = {28 78 6c 4c 65 73 73 20 58 6f 72 20 28 2d 38 35 39 20 2d 20 2d 38 37 38 23 29 } //01 00  (xlLess Xor (-859 - -878#)
		$a_01_4 = {28 78 6c 49 4d 45 4d 6f 64 65 4e 6f 43 6f 6e 74 72 6f 6c 20 41 6e 64 20 78 6c 44 61 74 61 41 6e 64 4c 61 62 65 6c 29 } //01 00  (xlIMEModeNoControl And xlDataAndLabel)
		$a_01_5 = {49 6e 53 74 72 28 62 31 63 49 46 45 36 2c 20 4c 58 51 50 5f 39 52 6b 62 5f 6d 6d 31 2c 20 4b 78 4e 41 54 39 49 6a 68 77 64 71 53 76 43 29 } //00 00  InStr(b1cIFE6, LXQP_9Rkb_mm1, KxNAT9IjhwdqSvC)
	condition:
		any of ($a_*)
 
}