
rule TrojanDownloader_O97M_Obfuse_MH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 35 28 22 68 6f 77 6b 6d 77 68 6f 77 6b 6d 69 6e 6d 68 6f 77 6b 6d 67 6d 68 6f 77 6b 6d 74 73 3a 57 68 6f 77 6b 6d 69 6e 33 68 6f 77 6b 6d 32 5f 50 68 6f 77 6b 6d 72 68 6f 77 6b 6d 6f 63 65 68 6f 77 6b 6d 73 73 68 6f 77 6b 6d 22 29 29 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 38 2c 90 00 } //01 00 
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 90 02 35 2c 20 22 68 6f 77 6b 6d 22 2c 20 22 22 29 90 00 } //01 00 
		$a_03_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 90 01 01 20 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}