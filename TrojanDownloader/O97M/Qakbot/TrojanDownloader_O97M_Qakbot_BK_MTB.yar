
rule TrojanDownloader_O97M_Qakbot_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 61 35 44 39 33 79 20 26 20 22 20 22 20 26 20 61 5a 4f 65 38 61 } //01 00 
		$a_01_1 = {3d 20 22 31 30 2e 32 33 2e 33 31 2e 33 2e 30 2e 32 39 2e 31 30 2e 32 39 22 } //01 00 
		$a_01_2 = {3d 20 53 70 6c 69 74 28 61 77 6f 51 6e 32 2c 20 22 2e 22 29 } //01 00 
		$a_01_3 = {3d 20 61 6d 47 70 69 28 61 33 5a 6c 57 47 28 61 63 58 54 44 30 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 31 30 2e 32 33 2e 33 31 2e 33 2e 30 2e 32 39 2e 31 30 2e 32 39 22 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 61 64 4e 41 6a 20 26 20 22 20 22 20 26 20 61 32 55 71 69 6b } //01 00 
		$a_01_2 = {3d 20 53 70 6c 69 74 28 61 33 64 6d 69 2c 20 22 2e 22 29 } //01 00 
		$a_01_3 = {43 61 6c 6c 20 61 42 30 6e 76 64 28 61 32 55 71 69 6b 2c 20 61 68 72 55 38 56 28 61 57 66 6a 48 67 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_BK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 22 78 73 22 20 26 20 61 63 66 38 59 } //01 00 
		$a_01_1 = {26 20 22 63 6f 6d 22 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 61 79 61 58 49 28 } //01 00 
		$a_03_3 = {26 20 61 74 5a 68 51 28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 6f 54 41 36 53 20 26 20 90 02 0a 20 26 20 61 6f 54 41 36 53 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_BK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 61 4d 53 49 4f 20 26 20 22 5c 6d 31 2e 78 73 6c 22 } //01 00 
		$a_01_1 = {3d 20 61 4d 53 49 4f 20 26 20 22 5c 6d 31 2e 63 6f 6d 22 } //01 00 
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00 
		$a_01_3 = {61 64 46 57 41 2e 72 75 6e 20 61 58 6f 34 76 70 20 26 20 61 52 6c 4d 79 78 28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 6d 45 32 61 6b 20 26 20 61 39 44 7a 35 74 20 26 20 61 6d 45 32 61 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_BK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 61 53 47 72 30 77 20 26 20 22 78 73 22 20 26 20 61 63 66 38 59 } //01 00 
		$a_01_1 = {3d 20 61 53 47 72 30 77 20 26 20 22 63 6f 6d 22 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 61 79 61 58 49 28 61 78 42 54 43 46 2c 20 61 6f 6c 65 30 29 } //01 00 
		$a_01_3 = {3d 20 61 78 42 54 43 46 20 26 20 61 74 5a 68 51 28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 6f 54 41 36 53 20 26 20 61 6f 6c 65 30 20 26 20 61 6f 54 41 36 53 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_BK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 61 39 74 31 6d 38 20 26 20 22 5c 68 31 2e 78 73 6c 22 } //01 00 
		$a_01_1 = {3d 20 61 39 74 31 6d 38 20 26 20 22 5c 68 31 2e 63 6f 6d 22 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 61 71 54 66 35 64 28 61 34 55 43 77 6b 2c 20 61 58 6d 4b 61 30 29 } //01 00 
		$a_01_3 = {3d 20 61 34 55 43 77 6b 20 26 20 61 44 36 33 42 4e 28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 67 48 75 38 20 26 20 61 58 6d 4b 61 30 20 26 20 61 67 48 75 38 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_BK_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00 
		$a_01_1 = {3d 20 61 47 4a 78 56 28 61 6a 63 39 52 7a 28 61 63 42 4e 33 28 61 4c 56 79 48 29 2c 20 31 30 29 29 } //01 00 
		$a_01_2 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 61 46 6f 65 73 } //01 00 
		$a_01_3 = {3d 20 43 68 72 28 22 22 20 26 20 61 42 75 30 7a 73 20 26 20 22 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_BK_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 31 30 2e 32 33 2e 33 31 2e 33 2e 30 2e 32 39 2e 31 30 2e 32 39 22 } //01 00 
		$a_01_1 = {3d 20 53 70 6c 69 74 28 61 39 7a 6f 4f 2c 20 22 2e 22 29 } //01 00 
		$a_01_2 = {3d 20 53 70 6c 69 74 28 61 70 42 66 78 57 2c 20 22 2e 22 29 } //01 00 
		$a_01_3 = {53 68 65 6c 6c 20 61 59 48 6c 6b 20 26 20 22 20 22 20 26 20 61 62 79 53 4c 34 } //01 00 
		$a_01_4 = {53 68 65 6c 6c 20 61 49 5a 4a 7a 6c 20 26 20 22 20 22 20 26 20 61 38 74 52 62 71 } //01 00 
		$a_03_5 = {3d 20 61 65 41 46 53 28 61 45 41 4a 62 28 90 02 0a 28 90 02 0a 29 2c 20 31 31 31 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}