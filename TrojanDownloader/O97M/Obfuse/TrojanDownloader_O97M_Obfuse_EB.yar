
rule TrojanDownloader_O97M_Obfuse_EB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 90 02 14 29 90 00 } //01 00 
		$a_03_1 = {2b 20 22 33 32 5f 50 72 6f 63 65 73 73 22 29 2e 43 72 65 61 74 65 90 01 01 20 90 02 14 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 4e 75 6c 6c 2c 20 90 02 14 2c 90 00 } //01 00 
		$a_01_2 = {2b 20 22 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //00 00  + "32_ProcessStartup")
	condition:
		any of ($a_*)
 
}