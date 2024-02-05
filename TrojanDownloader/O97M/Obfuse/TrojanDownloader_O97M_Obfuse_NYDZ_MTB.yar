
rule TrojanDownloader_O97M_Obfuse_NYDZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NYDZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 63 6f 6d 2f 31 37 2f 61 6e 64 72 65 33 34 2e 65 78 90 0a 3c 00 68 74 74 70 3a 2f 2f 73 63 61 6c 61 64 65 76 65 6c 6f 70 6d 65 6e 74 73 2e 73 63 61 6c 61 64 65 76 63 6f 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 75 6e } //01 00 
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 65 6c 65 63 74 69 6f 6e 6f 76 65 72 2e 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}