
rule TrojanDownloader_O97M_Donoff_RP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 3a 61 76 61 72 2e 6f 70 65 6e 22 67 65 74 22 2c 22 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 2e 65 65 2f 72 2f 72 6d 78 38 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_RP_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 3a 2f 2f 33 2e 31 31 32 2e 32 34 33 2e 32 38 2f 74 75 6e 2f 37 37 30 35 32 32 31 32 30 35 2e 62 61 74 22 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_RP_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 78 6f 6f 6d 65 72 2e 76 69 72 67 69 6c 69 6f 2e 69 74 2f 6c 75 64 6f 72 6d 69 6f 2f 64 6f 77 6e 6c 6f 61 64 2e 68 74 6d } //01 00 
		$a_01_1 = {45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 20 22 43 3a 5c 44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 65 72 72 6f 72 66 69 78 2e 62 61 74 } //01 00 
		$a_01_2 = {66 72 6d 43 68 65 73 73 58 2e 52 6f 6f 74 4f 4c 45 } //00 00 
	condition:
		any of ($a_*)
 
}