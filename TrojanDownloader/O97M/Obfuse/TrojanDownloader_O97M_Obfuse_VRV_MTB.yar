
rule TrojanDownloader_O97M_Obfuse_VRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.VRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 77 22 20 2b 20 22 2e 22 20 2b 20 22 62 22 20 2b 20 22 69 22 20 2b 20 22 74 22 20 2b 20 22 6c 22 20 2b 20 22 79 22 20 2b 20 22 2e 22 20 2b 20 22 63 22 20 2b 20 22 6f 22 20 2b 20 22 6d 2f 68 77 64 69 6e 6e 77 73 6e 64 64 77 6d 77 64 64 77 6f 6d 77 71 77 68 64 61 22 2c 20 5f } //01 00 
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 5f 0d 0a 20 20 28 30 2c 20 22 6f 70 65 6e 22 2c 20 6b 6f 6b 6f 2c 20 22 68 22 20 5f } //01 00 
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 5f 0d 0a 53 68 65 6c 6c 45 78 65 63 75 74 65 20 5f 0d 0a 4c 69 62 20 5f 0d 0a 22 53 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 5f } //00 00 
	condition:
		any of ($a_*)
 
}