
rule TrojanDownloader_O97M_Dridex_PSTT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 43 74 43 53 49 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 53 6f 55 71 48 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 59 75 70 62 41 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 4a 6c 67 66 76 5a 72 74 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 51 72 41 46 70 74 79 73 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 59 46 5a 4e 70 69 75 49 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 4b 67 6d 73 67 4a 62 67 50 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 4c 77 53 41 71 6b 77 74 5a 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 66 4b 41 7a 58 56 6b 54 65 43 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 46 54 67 4f 43 4e 4f 72 46 71 54 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 71 5a 79 45 70 52 44 6e 6f 53 52 55 4f 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 48 77 45 67 6a 59 70 54 65 6d 7a 54 49 6b 46 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Dridex_PSTT_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 61 64 44 50 43 6e 59 46 47 45 53 42 68 75 55 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}