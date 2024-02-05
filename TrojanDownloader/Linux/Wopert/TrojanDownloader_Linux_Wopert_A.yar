
rule TrojanDownloader_Linux_Wopert_A{
	meta:
		description = "TrojanDownloader:Linux/Wopert.A,SIGNATURE_TYPE_MACROHSTR_EXT,0f 00 0f 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {64 65 63 72 79 70 74 28 44 65 63 6f 64 65 36 34 28 22 } //08 00 
		$a_01_1 = {28 28 28 55 42 6f 75 6e 64 28 62 49 6e 29 20 2b 20 31 29 20 5c 20 34 29 20 2a 20 33 29 20 2d 20 31 29 } //02 00 
		$a_01_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 } //02 00 
		$a_01_3 = {4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 66 69 72 73 74 2c 20 31 29 20 3d 20 43 68 72 28 } //00 00 
		$a_00_4 = {cf 18 00 00 } //78 20 
	condition:
		any of ($a_*)
 
}