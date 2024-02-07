
rule TrojanDownloader_O97M_Obfuse_JP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 09 20 2b 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 90 02 09 2e 43 61 70 74 69 6f 6e 20 2b 20 90 02 09 29 2e 43 72 65 61 74 65 28 90 02 34 2c 90 00 } //01 00 
		$a_03_1 = {2b 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 90 02 09 2e 43 61 70 74 69 6f 6e 20 2b 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 90 00 } //01 00 
		$a_01_2 = {53 68 6f 77 57 69 6e 64 6f 77 21 20 5f } //00 00  ShowWindow! _
	condition:
		any of ($a_*)
 
}