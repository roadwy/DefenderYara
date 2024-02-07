
rule TrojanDownloader_O97M_Obfuse_DQ{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DQ,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 90 02 10 20 2b 20 90 02 10 20 2b 20 90 02 10 29 2e 20 5f 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 90 01 01 20 5f 90 00 } //01 00 
		$a_01_2 = {2b 20 22 77 69 6e 6d 22 20 2b 20 22 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //00 00  + "winm" + "gmts:Win32_ProcessStartup")
	condition:
		any of ($a_*)
 
}