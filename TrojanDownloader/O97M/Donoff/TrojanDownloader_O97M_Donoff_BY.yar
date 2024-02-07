
rule TrojanDownloader_O97M_Donoff_BY{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BY,SIGNATURE_TYPE_MACROHSTR_EXT,ffffffcd 00 ffffffcd 00 06 00 00 64 00 "
		
	strings :
		$a_02_0 = {48 54 54 50 2e 90 02 10 41 64 6f 64 62 90 00 } //64 00 
		$a_02_1 = {2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 90 02 40 2e 57 72 69 74 65 90 02 40 2e 73 61 76 65 74 6f 66 69 6c 65 90 02 70 2e 4f 70 65 6e 90 00 } //03 00 
		$a_02_2 = {53 75 62 20 90 02 10 6f 70 65 6e 28 29 90 00 } //03 00 
		$a_02_3 = {50 75 62 6c 69 63 20 53 75 62 20 42 6f 6f 74 90 02 05 28 29 90 00 } //02 00 
		$a_00_4 = {3d 20 22 61 22 20 4f 72 20 4d 69 64 28 } //02 00  = "a" Or Mid(
		$a_03_5 = {3d 20 53 70 6c 69 74 28 22 90 0f b0 01 90 10 90 00 22 2c 20 22 90 0f 09 00 90 10 09 00 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}