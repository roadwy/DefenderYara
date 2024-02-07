
rule TrojanDownloader_O97M_Obfuse_FA{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FA,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 09 00 00 02 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 90 02 01 90 02 20 2c 20 90 02 25 2c 20 90 00 } //01 00 
		$a_01_1 = {3d 20 22 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 22 } //01 00  = "mts:Win32_Proces"
		$a_01_2 = {3d 20 22 6d 74 73 22 20 2b 20 22 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 22 } //01 00  = "mts" + ":Win32_Proces"
		$a_01_3 = {2b 20 22 3a 57 69 6e 33 32 22 20 2b 20 22 5f 50 72 6f 63 65 73 22 } //01 00  + ":Win32" + "_Proces"
		$a_01_4 = {2b 20 22 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 } //01 00  + "mgmts:Win32_Process"
		$a_01_5 = {2b 20 22 6d 67 6d 74 73 3a 57 69 6e 22 20 2b 20 22 33 32 5f 50 72 6f 63 65 73 73 22 } //01 00  + "mgmts:Win" + "32_Process"
		$a_01_6 = {2b 20 22 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 } //01 00  + "mts:Win32_Process"
		$a_01_7 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 22 77 69 6e 6d 67 22 20 5f } //01 00  CreateObject(("winmg" _
		$a_03_8 = {53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 90 02 14 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}