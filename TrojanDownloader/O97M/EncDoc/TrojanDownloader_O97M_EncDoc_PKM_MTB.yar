
rule TrojanDownloader_O97M_EncDoc_PKM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 72 6c 3d 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 61 79 2d 62 6e 6b 32 75 2e 63 6f 6d 2f 66 69 6c 65 73 2f 65 6e 71 75 69 72 79 2e 7a 69 70 } //01 00 
		$a_01_1 = {63 3a 5c 75 73 65 72 73 5c 22 26 65 6e 76 69 72 6f 6e 28 22 75 73 65 72 6e 61 6d 65 22 29 26 22 5c 64 6f 63 75 6d 65 6e 74 73 5c 22 26 22 65 6e 71 75 69 72 79 2e 65 78 65 } //01 00 
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 6c 69 62 22 75 72 6c 6d 6f 6e 22 61 6c 69 61 73 22 75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_PKM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 77 20 68 69 20 73 5e 6c 65 65 70 20 2d 53 65 20 33 31 3b 53 74 61 72 74 2d 42 69 74 73 54 72 5e 61 6e 5e 73 66 65 72 20 2d 53 6f 75 72 63 65 } //02 00 
		$a_01_1 = {68 74 74 60 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 31 33 34 39 38 39 39 39 34 35 36 31 33 37 32 38 30 2f 39 32 34 39 34 30 35 30 35 35 31 37 37 38 35 31 31 38 2f 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 60 78 65 } //01 00 
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 75 73 65 6d 6f 72 6e 69 6e 67 2e 65 60 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}