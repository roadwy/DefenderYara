
rule TrojanDownloader_Linux_Adnel_gen_D{
	meta:
		description = "TrojanDownloader:Linux/Adnel.gen!D,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {22 75 72 6c 6d 6f 6e 22 20 5f 90 02 04 41 6c 69 61 73 20 5f 90 02 04 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 5f 90 00 } //01 00 
		$a_03_1 = {22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 5f 90 02 04 41 6c 69 61 73 20 5f 90 02 04 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 90 00 } //01 00 
		$a_01_2 = {36 45 36 35 37 30 36 46 24 } //01 00 
		$a_01_3 = {34 35 35 38 34 35 32 45 } //01 00 
		$a_01_4 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 48 65 78 32 53 74 72 28 22 } //00 00 
	condition:
		any of ($a_*)
 
}