
rule TrojanDownloader_O97M_Obfuse_DS{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DS,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 4e 75 6c 6c 2c 20 90 02 20 2c 20 70 72 6f 63 65 73 73 69 64 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 90 01 01 20 5f 90 00 } //01 00 
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //00 00  = GetObject("winmgmts:Win32_ProcessStartup")
	condition:
		any of ($a_*)
 
}