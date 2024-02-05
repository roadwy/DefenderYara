
rule TrojanDownloader_O97M_Emotet_AMDB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 5e 68 5e 74 5e 61 20 68 5e 74 5e 74 70 3a 2f 5e 2f 30 5e 78 35 5e 62 66 5e 30 37 5e 36 61 5e 38 2f 73 65 2f 73 2e 68 74 6d 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Emotet_AMDB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 79 68 6a 6c 73 77 6c 65 2e 76 62 73 } //01 00 
		$a_01_1 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 75 67 68 6c 64 73 6b 62 68 6e 2e 62 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Emotet_AMDB_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 79 73 57 6f 77 36 34 5c 90 02 2f 5c 57 69 6e 64 6f 77 73 5c 90 02 2f 72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 32 2e 65 78 65 90 02 2f 22 68 74 74 70 90 02 ff 22 68 74 74 70 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Emotet_AMDB_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 66 65 2f 66 2e 68 74 6d 6c } //01 00 
		$a_01_1 = {63 6d 64 20 2f 63 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 71 77 2f 61 73 2f 73 65 2e 68 74 6d 6c } //01 00 
		$a_01_2 = {63 6d 64 20 2f 63 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 7a 71 71 77 2f 7a 61 61 73 2f 66 65 2e 68 74 6d 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Emotet_AMDB_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f 6e 65 77 22 26 22 61 66 66 6f 72 64 22 26 22 61 62 6c 65 68 6f 22 26 22 75 73 69 6e 22 26 22 67 70 72 6f 67 72 22 26 22 61 6d 2e 63 22 26 22 6f 6d 2f 4e 66 22 26 22 62 70 6b 22 26 22 75 46 22 26 22 58 53 53 2f 4e 68 22 26 22 66 22 26 22 6d 4e 2e 70 22 26 22 6e 67 22 } //01 00 
		$a_01_1 = {68 74 22 26 22 74 70 22 26 22 73 3a 2f 2f 6d 69 22 26 22 78 64 69 67 22 26 22 69 74 22 26 22 61 6c 2e 6e 22 26 22 65 74 2f 67 22 26 22 5a 75 67 22 26 22 71 69 66 22 26 22 52 44 2f 4e 22 26 22 68 22 26 22 66 6d 22 26 22 4e 2e 70 22 26 22 6e 67 22 } //01 00 
		$a_01_2 = {68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f 70 74 22 26 22 6e 61 63 61 22 26 22 6d 61 72 22 26 22 61 2e 6f 22 26 22 72 67 2e 62 22 26 22 72 2f 6b 22 26 22 65 36 22 26 22 69 79 76 38 22 26 22 6f 30 22 26 22 55 66 22 26 22 53 2f 4e 22 26 22 68 66 22 26 22 6d 4e 2e 70 22 26 22 6e 67 22 } //00 00 
	condition:
		any of ($a_*)
 
}