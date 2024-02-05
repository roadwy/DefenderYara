
rule _#ALF_TrojanDownloader_O97M_Donoff{
	meta:
		description = "!#ALF:TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 72 22 20 26 20 22 22 20 26 20 22 74 66 22 } //01 00 
		$a_01_1 = {6f 22 20 2b 20 22 72 64 2e 41 70 70 6c 69 63 61 74 69 6f 22 20 2b 20 22 6e 22 20 2b } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ALF_TrojanDownloader_O97M_Donoff_2{
	meta:
		description = "!#ALF:TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2e 56 22 } //01 00 
		$a_01_1 = {2b 20 22 42 45 22 } //01 00 
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 63 6f 6e 6e 65 63 74 2e 62 75 73 69 6e 65 73 73 68 65 6c 70 61 2d 7a 2e 63 6f 6d 2f 64 61 6e 61 2f 68 6f 6d 65 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ALF_TrojanDownloader_O97M_Donoff_3{
	meta:
		description = "!#ALF:TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {29 20 4d 6f 64 20 32 36 29 20 2b 20 36 35 29 } //01 00 
		$a_01_1 = {20 2d 20 36 35 20 2b 20 } //01 00 
		$a_01_2 = {20 26 20 43 68 72 28 28 28 } //01 00 
		$a_01_3 = {43 61 73 65 20 36 35 20 54 6f 20 39 30 } //01 00 
		$a_01_4 = {43 61 73 65 20 39 37 20 54 6f 20 31 32 32 } //01 00 
		$a_01_5 = {20 2d 20 39 37 20 2b 20 } //01 00 
		$a_01_6 = {29 20 4d 6f 64 20 32 36 29 20 2b 20 39 37 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ALF_TrojanDownloader_O97M_Donoff_4{
	meta:
		description = "!#ALF:TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 73 65 20 41 73 63 28 22 41 22 29 20 2b 20 31 33 20 54 6f 20 41 73 63 28 22 4d 22 29 20 2b 20 31 33 0d 0a } //01 00 
		$a_01_1 = {43 61 73 65 20 41 73 63 28 22 4e 22 29 20 2d 20 31 33 20 54 6f 20 41 73 63 28 22 5a 22 29 20 2d 20 31 33 0d 0a } //01 00 
		$a_01_2 = {20 3d 20 31 33 20 2f 20 30 0d 0a } //01 00 
		$a_01_3 = {2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f 0d 0a } //01 00 
		$a_01_4 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 30 } //00 00 
	condition:
		any of ($a_*)
 
}