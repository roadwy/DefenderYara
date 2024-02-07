
rule TrojanDownloader_O97M_Obfuse_EO{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EO,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {44 69 6d 20 90 02 20 20 41 73 20 43 75 72 72 65 6e 63 79 90 00 } //01 00 
		$a_02_1 = {53 74 72 52 65 76 65 72 73 65 28 53 74 72 52 65 76 65 72 73 65 28 90 02 20 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_EO_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EO,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 90 02 01 20 90 02 10 20 2b 20 90 02 25 20 2b 20 90 00 } //01 00 
		$a_03_1 = {47 65 74 4f 62 6a 65 63 74 28 90 02 10 20 2b 20 22 53 74 61 22 20 2b 20 22 72 74 75 70 22 29 90 00 } //01 00 
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 20 2b 20 22 53 74 61 22 20 2b 20 22 72 74 75 70 22 29 29 } //01 00  GetObject("winmgmts:Win32_Process" + "Sta" + "rtup"))
		$a_01_3 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 22 20 2b 20 22 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 20 2b 20 22 53 74 61 22 20 2b 20 22 72 74 75 70 22 29 29 } //01 00  GetObject("winm" + "gmts:Win32_Process" + "Sta" + "rtup"))
		$a_01_4 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 22 20 2b 20 22 67 6d 74 73 3a 57 22 20 2b 20 22 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 20 2b 20 22 53 74 61 22 20 2b 20 22 72 74 75 70 22 29 29 } //01 00  GetObject("winm" + "gmts:W" + "in32_Process" + "Sta" + "rtup"))
		$a_03_5 = {53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 90 02 14 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}