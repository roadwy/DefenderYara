
rule TrojanDownloader_O97M_Obfuse_ARY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ARY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 28 43 4c 6e 67 28 28 } //01 00  = Join(Array(Chr(CLng((
		$a_03_1 = {3d 20 57 65 65 6b 64 61 79 28 90 02 16 29 90 00 } //01 00 
		$a_03_2 = {3d 20 53 70 6c 69 74 28 90 02 10 2c 20 90 02 10 2c 20 90 02 10 29 90 00 } //01 00 
		$a_01_3 = {3d 20 49 73 44 61 74 65 28 43 4c 6e 67 28 28 } //01 00  = IsDate(CLng((
		$a_01_4 = {44 65 62 75 67 2e 50 72 69 6e 74 } //01 00  Debug.Print
		$a_03_5 = {3d 20 52 65 70 6c 61 63 65 28 90 02 18 2c 20 90 02 18 2c 20 90 02 18 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}