
rule TrojanDownloader_O97M_Donoff_DJ{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DJ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 6f 4c 6f 76 65 20 3d 20 61 61 20 58 6f 72 20 62 62 } //01 00  DoLove = aa Xor bb
		$a_02_1 = {3d 20 53 70 6c 69 74 28 90 02 0f 2c 20 22 50 52 45 43 48 49 4c 22 29 90 00 } //01 00 
		$a_02_2 = {2c 20 22 73 22 20 2b 20 90 02 0f 20 2b 20 22 69 6c 65 22 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}