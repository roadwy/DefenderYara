
rule TrojanDownloader_O97M_Obfuse_KW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 14 28 22 77 51 41 23 69 6e 6d 51 41 23 67 6d 51 41 23 74 73 51 41 23 3a 51 41 23 57 51 41 23 69 6e 51 41 23 33 51 41 23 32 51 41 23 5f 51 41 23 50 72 51 41 23 6f 51 41 23 51 41 23 63 65 51 41 23 73 51 41 23 73 22 29 29 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 20 90 02 38 2c 90 00 } //01 00 
		$a_03_2 = {28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 90 02 14 29 20 2b 90 00 } //01 00 
		$a_01_3 = {53 68 6f 77 57 69 6e 64 6f 77 21 20 5f } //00 00  ShowWindow! _
	condition:
		any of ($a_*)
 
}