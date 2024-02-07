
rule TrojanDownloader_O97M_Obfuse_MOY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MOY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } //01 00  .ShowWindow = CLng((
		$a_03_1 = {2e 43 72 65 61 74 65 20 90 02 20 2c 20 4e 75 6c 6c 2c 90 00 } //01 00 
		$a_03_2 = {53 65 74 20 90 02 20 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 90 02 20 29 2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f 90 00 } //01 00 
		$a_01_3 = {26 20 43 68 72 57 28 43 4c 6e 67 28 28 41 73 63 57 28 22 } //01 00  & ChrW(CLng((AscW("
		$a_01_4 = {44 65 62 75 67 2e 50 72 69 6e 74 20 } //01 00  Debug.Print 
		$a_03_5 = {3d 20 52 65 70 6c 61 63 65 28 90 02 20 2c 20 90 02 20 2c 20 90 02 20 29 90 00 } //01 00 
		$a_03_6 = {3d 20 53 70 6c 69 74 28 90 02 20 2c 20 90 02 20 2c 20 90 02 20 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}