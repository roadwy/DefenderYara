
rule TrojanDownloader_O97M_Obfuse_PAP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 10 28 90 02 03 29 20 26 20 22 2e 22 20 26 20 90 02 10 28 90 02 03 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29 90 00 } //01 00 
		$a_03_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 90 02 10 28 90 02 10 29 2c 20 46 61 6c 73 65 90 00 } //01 00 
		$a_03_2 = {2e 57 72 69 74 65 20 90 02 10 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 90 00 } //01 00 
		$a_03_3 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 90 02 10 2c 20 32 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}