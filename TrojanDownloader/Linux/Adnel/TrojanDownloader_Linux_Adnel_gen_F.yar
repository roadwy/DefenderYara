
rule TrojanDownloader_Linux_Adnel_gen_F{
	meta:
		description = "TrojanDownloader:Linux/Adnel.gen!F,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c 20 90 04 50 06 41 2d 5a 61 2d 7a 90 05 50 06 41 2d 5a 61 2d 7a 20 41 73 20 4c 6f 6e 67 90 00 } //01 00 
		$a_03_1 = {2d 20 41 73 63 28 4d 69 64 28 90 04 50 06 41 2d 5a 61 2d 7a 90 05 50 06 41 2d 5a 61 2d 7a 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}