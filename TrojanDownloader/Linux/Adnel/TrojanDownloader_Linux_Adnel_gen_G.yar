
rule TrojanDownloader_Linux_Adnel_gen_G{
	meta:
		description = "TrojanDownloader:Linux/Adnel.gen!G,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {27 3c 20 70 72 6f 74 65 63 74 65 64 20 62 79 20 77 77 77 2e 43 72 75 6e 63 68 43 6f 64 65 2e 64 65 } //01 00  '< protected by www.CrunchCode.de
		$a_01_1 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 0d 0a 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 20 4c 69 62 20 5f 0d 0a 22 75 72 6c 6d 6f 6e 22 } //01 00 
		$a_03_2 = {3d 20 53 68 65 6c 6c 28 90 05 20 06 41 2d 5a 61 2d 7a 2c 20 5f 0d 0a 31 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 41 75 74 6f 5f 4f 70 65 6e 0d 0a 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}