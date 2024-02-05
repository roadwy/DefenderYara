
rule TrojanDownloader_O97M_Obfuse_BPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 52 52 4f 52 20 21 21 21 22 3a 20 43 61 6c 6c 20 53 68 65 6c 6c 20 5f } //01 00 
		$a_01_1 = {4b 41 52 54 49 43 20 3d 20 22 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } //01 00 
		$a_01_2 = {54 49 54 41 54 20 3d 20 54 41 65 63 20 2b 20 54 59 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 20 3d 20 22 68 74 74 70 3a 2f 2f 34 47 50 2e 4d 45 2f 62 6c 74 63 2f 31 35 39 30 30 37 34 35 39 36 35 32 31 2e 74 78 74 22 } //01 00 
		$a_01_1 = {3d 20 57 69 6e 45 78 65 63 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 6d 73 68 74 61 20 22 20 26 20 7a 2c 20 30 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 6a 2e 6d 70 2f 90 02 28 22 90 00 } //01 00 
		$a_01_1 = {3a 20 53 68 65 6c 6c 20 28 22 70 69 6e 67 2e 65 78 65 22 29 } //01 00 
		$a_01_2 = {4d 73 67 42 6f 78 20 28 22 45 72 72 6f 72 21 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 72 61 32 20 3d 20 4e 61 6d 61 6b 42 6f 72 61 20 2b 20 6c 6f 72 61 } //01 00 
		$a_01_1 = {3d 20 22 20 68 74 74 70 73 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 62 69 74 6c 79 2e 63 6f 6d 2f 61 77 6b 64 68 69 6b 68 61 73 64 22 } //01 00 
		$a_01_2 = {52 75 6e 20 6c 6f 72 61 32 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 67 67 67 20 2b 20 6c 75 6c 75 6c 75 20 2b 20 74 69 74 69 74 69 20 2b 20 22 74 61 20 68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 90 02 1e 22 90 00 } //01 00 
		$a_01_1 = {3d 20 22 6d 22 } //01 00 
		$a_01_2 = {3d 20 22 73 22 } //01 00 
		$a_01_3 = {3d 20 22 68 22 } //01 00 
		$a_01_4 = {53 68 65 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 65 69 6e 6b 6f 6e 68 75 6e 2e 45 58 45 43 20 70 69 6e 67 73 } //01 00 
		$a_01_1 = {3d 20 22 20 48 22 20 2b 20 44 20 2b 20 44 20 2b 20 4c 20 2b 20 22 3a 2f 2f 22 20 2b 20 4b 20 2b 20 54 } //01 00 
		$a_01_2 = {70 69 6e 67 73 20 3d 20 58 20 2b 20 59 20 2b 20 5a 20 2b 20 44 20 2b 20 45 20 2b 20 46 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 41 61 59 79 4a 61 30 20 2b 20 41 61 59 79 4a 61 31 20 2b 20 41 61 59 79 4a 61 32 20 2b 20 41 61 59 79 4a 61 33 } //01 00 
		$a_01_1 = {3d 20 64 73 73 65 45 52 44 59 20 26 20 43 68 72 28 41 61 59 79 4a 61 28 41 64 59 44 4a 61 29 29 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 20 28 41 61 59 79 4a 61 35 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2f 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 40 6a 2e 6d 70 5c 6b 61 73 64 61 73 6a 78 69 61 6b 73 64 64 6b 61 64 73 64 73 6b 64 64 22 } //01 00 
		$a_01_1 = {3d 20 53 68 65 6c 6c 28 61 73 69 64 6d 61 69 73 6d 61 20 2b 20 50 73 69 64 6d 50 69 73 6d 50 2c 20 76 62 4d 69 6e 69 6d 69 7a 65 64 46 6f 63 75 73 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 56 50 68 70 67 52 51 5a 59 20 2b 20 4f 77 32 49 55 56 45 4f 61 20 2b 20 77 77 68 52 4b 42 39 34 4f 66 6c 42 45 48 56 68 75 20 2b 20 4f 66 6c 42 45 48 56 68 75 29 29 } //01 00 
		$a_01_1 = {4f 66 6c 42 45 48 56 68 75 20 3d 20 22 63 68 64 6d 62 6a 68 62 67 68 64 65 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 6a 22 20 2b 20 22 2e 22 20 2b 20 22 6d 22 20 2b 20 22 70 2f 22 } //01 00 
		$a_01_1 = {3a 20 6d 65 69 6e 6b 6f 6e 68 75 6e 2e 45 58 45 43 20 70 69 6e 67 73 } //01 00 
		$a_03_2 = {3d 20 22 61 22 20 2b 20 22 73 22 20 2b 20 22 64 22 20 2b 20 22 69 22 20 2b 20 22 6d 22 20 2b 20 22 61 22 20 2b 20 22 77 22 20 2b 20 22 78 22 20 2b 20 22 90 02 1e 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 20 68 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 74 22 } //01 00 
		$a_01_1 = {59 61 68 6f 6f 64 69 31 31 31 31 20 3d 20 70 64 61 73 31 20 2b 20 6b 6f 32 20 2b 20 6b 6f 32 33 20 2b 20 6f 6b 33 } //01 00 
		$a_01_2 = {59 61 68 6f 6f 64 69 2e 53 54 41 52 54 4f 4e } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 42 41 2e 53 68 65 6c 6c 28 4b 43 4b 52 30 68 4a 69 50 20 2b 20 69 4a 6c 50 76 73 6c 6e 70 20 2b 20 73 6d 59 31 44 63 64 66 6c 20 2b 20 58 67 64 6c 49 68 4f 57 59 29 29 } //01 00 
		$a_01_1 = {3d 20 41 70 77 41 36 46 62 47 58 20 26 20 53 74 72 52 65 76 65 72 73 65 28 4d 69 64 28 77 6c 61 52 71 67 4c 61 77 2c 20 47 37 43 76 64 46 73 4c 6a 2c 20 32 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 20 68 74 74 70 3a 2f 2f 25 38 32 33 34 25 38 32 33 34 40 6a 2e 6d 70 2f 64 64 6b 73 6c 61 73 64 6a 61 6c 73 6a 64 61 73 6e 77 22 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 6d 79 43 68 72 79 73 6c 65 72 20 2b 20 53 69 73 74 65 72 73 52 61 6e 67 65 52 6f 76 65 72 } //01 00 
		$a_01_2 = {3a 20 53 68 65 6c 6c 20 64 65 63 72 79 70 74 28 22 76 6f 74 6d 22 2c 20 22 36 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 6a 2e 6d 70 2f 77 61 73 61 6a 73 69 64 6a 61 73 64 61 73 64 6b 6f 6f 63 73 22 } //01 00 
		$a_01_1 = {3d 20 63 61 6c 63 20 2b 20 63 61 6c 63 31 20 2b 20 63 61 6c 63 32 20 2b 20 63 61 6c 63 33 20 2b 20 63 61 6c 63 34 20 2b 20 63 61 6c 63 35 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 20 63 61 6c 63 6d 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_15{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 65 20 68 74 74 70 3a 2f 2f 61 63 68 6f 74 65 69 73 2e 63 6f 6d 2e 62 72 2f 69 6d 61 67 65 73 2f 61 74 65 6e 64 69 6d 65 6e 74 6f 2e 74 78 74 22 } //01 00 
		$a_01_1 = {3d 20 57 6d 64 6d 65 31 20 2b 20 57 6d 64 6d 65 32 20 2b 20 57 6d 64 6d 65 33 20 2b 20 57 6d 64 6d 65 34 20 2b 20 57 6d 64 6d 65 35 20 2b 20 57 6d 64 6d 65 35 31 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 20 28 57 6d 64 6d 65 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_16{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 53 52 65 76 65 72 73 65 4d 6f 64 28 22 70 2f 2e 6d 40 6a 34 38 30 39 32 33 25 31 34 38 30 39 32 33 2f 31 3a 2f 74 70 68 74 20 22 29 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 53 74 72 52 65 76 65 72 73 65 28 53 52 65 76 65 72 73 65 4d 6f 64 28 22 74 61 73 68 20 6d 2f 63 64 20 63 6d 22 29 29 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 20 78 6d 6f 72 67 61 6e 64 64 3a } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_17{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 73 61 73 64 61 73 64 64 61 73 64 61 73 64 61 73 64 61 73 64 61 73 64 64 6b 61 6f 73 22 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 68 69 72 65 6d 65 29 2e 45 78 65 63 20 73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e 31 30 20 2b 20 73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e 31 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_18{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 22 22 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 } //01 00 
		$a_01_1 = {68 22 20 2b 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 5c 5c 22 20 2b 20 22 6a 2e 22 20 2b 20 22 6d 70 5c 22 20 2b 20 22 71 61 73 61 78 61 68 6e 6e 38 33 6a 73 38 78 61 73 78 6a 78 39 61 73 78 6a } //01 00 
		$a_01_2 = {53 68 65 6c 6c 20 22 50 69 6e 67 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_19{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 65 69 6e 6b 6f 6e 68 75 6e 31 2e 45 58 45 43 20 6c 69 73 74 65 6e 31 20 2b 20 6d 61 64 61 72 32 20 2b 20 6a 61 6e 75 33 20 2b 20 6a 61 6e 75 34 20 2b 20 66 61 6b 69 72 34 } //01 00 
		$a_01_1 = {53 65 74 20 6d 65 69 6e 6b 6f 6e 68 75 6e 31 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 22 20 2b 20 45 6e 44 65 63 72 79 70 74 4d 55 52 } //01 00 
		$a_01_2 = {66 61 6b 69 72 34 20 3d 20 45 6e 44 65 63 72 79 70 74 4d 55 52 28 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_20{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 71 70 71 2e 22 } //01 00 
		$a_01_1 = {3d 20 22 68 74 61 22 3a } //01 00 
		$a_01_2 = {53 68 65 6c 6c 20 28 4d 79 45 78 63 65 63 75 65 29 } //01 00 
		$a_01_3 = {3d 20 62 65 61 38 38 35 65 37 34 63 38 36 65 63 35 65 34 64 61 39 37 34 66 31 33 30 20 2b 20 62 65 61 38 38 35 65 37 34 63 38 36 65 63 35 65 34 64 61 39 37 34 66 31 33 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_21{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 6f 62 6a 2e 4a 61 6e 75 67 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 75 31 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 2c 20 22 68 74 74 70 73 3a 2f 2f 62 69 74 6c 79 2e 63 6f 6d 2f 65 79 77 75 69 71 64 62 6e 61 6d 73 64 67 6a 68 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //01 00 
		$a_01_1 = {53 65 74 20 4a 61 6e 75 67 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 20 5f } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_22{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 74 61 6c 61 74 75 77 61 31 20 2b 20 74 61 6c 61 74 75 77 61 32 20 2b 20 74 61 6c 61 74 75 77 61 33 20 2b 20 74 61 6c 61 74 75 77 61 34 20 2b 20 74 61 6c 61 74 75 77 61 35 } //01 00 
		$a_01_1 = {3d 20 22 68 22 20 26 20 48 6f 6e 65 79 20 2b 20 61 6e 69 6d 61 6c 32 20 2b 20 53 74 72 69 6e 67 28 32 2c 20 22 2f 22 29 20 2b 20 5a 75 6d 61 20 26 20 22 6a 2e 22 20 2b 20 73 6e 61 6b 65 20 2b 20 53 74 72 69 6e 67 28 33 2c 20 22 68 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_23{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 63 61 6c 63 73 65 78 6b 6f 6f 6b 6b } //01 00 
		$a_01_1 = {3d 20 22 74 70 3a 2f 2f 25 37 34 38 32 33 37 25 37 32 38 37 34 38 40 6a 2e 6d 70 2f 22 } //01 00 
		$a_01_2 = {3d 20 63 61 6c 63 73 65 63 79 6b 6f 39 5f 31 32 20 2b 20 63 61 6c 63 73 65 63 79 6b 6f 39 5f 34 32 5f 61 73 20 2b 20 6b 39 5f 34 32 5f 61 73 } //01 00 
		$a_01_3 = {3d 20 63 61 6c 63 73 65 78 6b 6f 20 2b 20 63 61 6c 63 73 65 63 79 6b 6f 6f 30 5f 53 44 5f 31 32 20 2b 20 70 69 6e 67 5f 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_24{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 78 67 67 67 67 67 64 6b 61 73 6f 64 6b 61 6f 73 22 } //01 00 
		$a_01_1 = {3d 20 22 6d 22 } //01 00 
		$a_01_2 = {3d 20 22 73 22 } //01 00 
		$a_01_3 = {3d 20 22 68 22 } //01 00 
		$a_01_4 = {3d 20 63 61 6c 63 31 20 2b 20 63 61 6c 63 32 20 2b 20 63 61 6c 63 33 20 2b 20 22 74 61 20 22 20 2b 20 63 61 6c 63 34 } //01 00 
		$a_01_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 78 65 63 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_25{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 52 65 70 6c 61 63 65 28 22 90 02 0c 22 2c 20 22 90 02 0c 22 2c 20 22 6c 79 2f 22 29 90 00 } //01 00 
		$a_01_1 = {3d 20 22 74 61 20 68 74 74 70 3a 2f 2f 25 32 30 25 32 30 25 32 30 25 32 30 32 30 25 32 30 32 30 25 32 30 32 30 25 32 30 32 30 25 32 30 40 62 69 74 2e 22 20 2b } //01 00 
		$a_01_2 = {3d 20 22 6d 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 73 22 29 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 68 22 29 20 2b } //01 00 
		$a_01_3 = {53 68 65 6c 6c 20 28 6a 61 63 6b 73 6f 6e 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_26{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 3a 2f 2f 25 35 30 25 35 30 25 35 30 25 35 30 40 6a 2e 6d 22 } //01 00 
		$a_01_1 = {3d 20 70 75 62 69 74 69 74 79 36 20 2b 20 70 75 62 69 74 69 74 79 37 20 2b 20 70 75 62 69 74 69 74 79 38 20 2b 20 70 75 62 69 74 69 74 79 39 20 2b 20 22 70 2f 61 73 61 61 73 64 6a 61 73 64 6b 61 6f 73 22 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 66 75 63 6b 7a 61 72 67 75 73 29 2e 45 78 65 63 20 72 65 73 6f 6e 73 77 68 79 31 30 20 2b 20 72 65 73 6f 6e 73 77 68 79 31 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_27{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 69 6b 72 32 38 38 39 74 66 64 39 6e 65 76 77 36 69 31 67 72 22 } //01 00 
		$a_01_1 = {3d 20 22 6d 22 } //01 00 
		$a_01_2 = {3d 20 22 73 22 } //01 00 
		$a_01_3 = {3d 20 22 68 22 } //01 00 
		$a_01_4 = {3d 20 68 75 67 67 69 31 20 2b 20 68 75 67 67 69 32 20 2b 20 68 75 67 67 69 33 20 2b 20 22 74 61 20 22 20 2b 20 68 75 67 67 69 34 } //01 00 
		$a_01_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 78 65 63 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_28{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 4c 41 53 31 5f 71 77 69 } //01 00 
		$a_01_1 = {3d 20 22 74 70 3a 2f 2f 25 37 34 38 32 33 37 25 37 32 38 37 34 38 40 6a 2e 6d 70 2f 22 } //01 00 
		$a_01_2 = {3d 20 6b 5f 44 61 6b 6f 30 5f 77 6b 6f 6b 64 31 5f 41 20 2b 20 6b 5f 44 61 6b 6f 30 5f 44 41 4c 53 44 5f 31 32 } //01 00 
		$a_01_3 = {3d 20 6f 73 64 61 73 6f 6c 78 73 6b 6f 69 65 5f 41 73 6a 64 6f 32 33 5f 61 73 64 20 2b 20 6b 5f 44 61 6b 6f 30 5f 53 44 5f 31 32 20 2b 20 6b 5f 44 61 6b 6f 30 5f 77 6b 6f 6b 64 31 5f 41 64 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_29{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6f 62 6a 2e 20 5f 90 0c 02 00 4d 61 69 6e 43 61 6c 6c 65 78 2e 20 5f 90 0c 02 00 52 75 6e 20 5f 90 0c 02 00 64 64 2c 20 30 90 00 } //01 00 
		$a_03_1 = {44 69 6d 20 6f 62 6a 20 41 73 20 4e 65 77 20 43 6c 61 73 73 32 90 0c 02 00 20 20 20 20 6f 62 6a 2e 20 5f 90 0c 02 00 20 20 20 20 47 65 74 4d 6f 72 65 4d 6f 64 75 6c 65 20 28 64 64 31 20 2b 20 64 64 32 20 2b 20 64 64 33 29 90 00 } //01 00 
		$a_01_2 = {63 2e 41 64 64 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 61 73 64 61 73 64 71 77 66 65 66 77 65 66 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_30{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 73 3a 2f 2f 25 34 30 25 34 30 40 6a 2e 6d 70 2f 61 37 73 38 64 61 73 67 64 68 73 61 73 61 64 66 78 63 22 } //02 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 68 69 72 65 6d 65 29 2e 45 78 65 63 20 73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e 31 30 20 2b 20 73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e 31 31 } //01 00 
		$a_01_2 = {3d 20 22 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 73 61 73 64 61 78 61 73 78 64 61 73 61 73 64 64 6b 61 6f 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_31{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 57 73 68 53 68 65 6c 6c 2e 45 78 65 63 28 63 61 6c 63 73 65 78 6b 6f 6f 6b 6b 29 } //01 00 
		$a_01_1 = {3d 20 22 74 70 3a 2f 2f 25 38 39 38 39 32 33 38 34 39 25 38 39 38 39 32 33 38 34 39 40 6a 2e 6d 70 2f 22 } //01 00 
		$a_01_2 = {3d 20 63 61 6c 63 73 65 63 79 6b 6f 39 5f 31 32 20 2b 20 63 61 6c 63 73 65 63 79 6b 6f 39 5f 34 32 5f 61 73 20 2b 20 6b 39 5f 34 32 5f 61 73 } //01 00 
		$a_01_3 = {3d 20 63 61 6c 63 73 65 78 6b 6f 20 2b 20 63 61 6c 63 73 65 63 79 6b 6f 6f 30 5f 53 44 5f 31 32 20 2b 20 70 69 6e 67 5f 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_32{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 6c 49 43 61 65 75 68 73 4c 20 2b 20 4a 4e 50 37 52 4d 48 67 6d 20 2b 20 74 68 56 72 72 33 4a 50 38 20 2b 20 43 73 59 52 35 65 32 4c 71 29 29 } //01 00 
		$a_01_1 = {49 66 20 53 74 72 52 65 76 65 72 73 65 28 22 49 4f 51 64 51 79 62 76 63 7a 6e 22 29 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 22 71 54 54 43 71 75 6f 65 75 59 22 29 20 54 68 65 6e 20 45 6e 64 } //01 00 
		$a_01_2 = {43 73 59 52 35 65 32 4c 71 20 3d 20 22 63 63 6f 6d 70 6c 65 72 6d 78 6a 64 61 6a 73 65 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_33{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 64 61 73 32 66 64 61 73 64 78 7a 63 7a 63 22 } //02 00 
		$a_01_1 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 64 61 73 36 35 37 78 7a 63 67 68 7a 67 68 61 73 22 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 20 74 6f 6d 61 6c 61 20 2b 20 6b 6f 6b 64 61 73 6f 64 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_34{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 52 65 70 6c 61 63 65 28 22 90 02 0c 22 2c 20 22 90 02 0c 22 2c 20 22 6c 79 2f 22 29 90 00 } //01 00 
		$a_01_1 = {3d 20 22 74 61 22 20 2b 20 22 20 68 22 20 2b 20 53 74 72 69 6e 67 28 32 2c 20 22 74 22 29 20 2b 20 22 70 3a 2f 2f 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 62 22 29 20 2b 20 22 69 74 2e 22 20 2b } //01 00 
		$a_01_2 = {3d 20 22 6d 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 73 22 29 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 68 22 29 20 2b } //01 00 
		$a_01_3 = {53 68 65 6c 6c 20 28 43 6f 6d 69 6e 67 74 6f 41 6d 65 72 69 63 61 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_35{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 78 78 20 3d 20 50 44 46 31 20 2b 20 50 44 46 32 20 2b 20 50 44 46 33 } //01 00 
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6d 61 67 6f 6f 67 20 2b 20 6d 61 67 6f 6f 67 31 29 } //01 00 
		$a_03_2 = {26 20 22 70 73 3a 2f 2f 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 22 20 26 20 22 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 22 20 26 20 22 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 22 20 26 20 90 02 08 20 2b 20 90 02 08 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 2f 22 29 20 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_36{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 6c 6f 64 68 69 20 2b 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 25 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 40 6a 2e 6d 70 2f 22 20 2b 20 22 66 76 67 6a 61 64 61 67 6a 22 20 2b 20 22 64 62 67 76 61 68 73 6b 73 61 64 67 6b 61 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 22 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 22 3a 20 53 68 65 6c 6c 20 22 63 61 6c 63 } //01 00 
		$a_01_2 = {3d 20 28 41 63 74 69 76 65 50 72 65 73 65 6e 74 61 74 69 6f 6e 2e 50 61 74 68 20 26 20 22 5c 74 65 73 74 2e 78 6c 73 78 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_37{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 40 20 5f 0d 0a 4e 61 6d 61 6b 42 6f 72 61 20 5f 0d 0a 2c 20 5f 0d 0a 6c 6f 72 61 32 } //01 00 
		$a_01_2 = {22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 61 68 64 6a 69 61 69 61 61 61 72 71 61 77 6e } //01 00 
		$a_01_3 = {22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 61 68 64 6a 69 61 69 61 61 77 6e } //01 00 
		$a_01_4 = {22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 61 68 64 6a 69 61 69 77 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_38{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 73 65 78 74 61 2e 22 } //01 00 
		$a_01_1 = {3d 20 22 68 74 61 22 } //01 00 
		$a_03_2 = {4d 5f 53 4f 69 4d 20 3d 20 90 02 08 47 4b 4a 48 67 6b 68 67 4b 48 4a 47 6b 4f 69 4d 90 02 0b 20 2b 20 90 02 08 47 4b 4a 48 67 6b 68 67 4b 48 4a 47 6b 4f 69 4d 5f 31 90 02 08 20 2b 20 90 02 08 47 4b 4a 48 67 6b 68 67 4b 48 4a 47 6b 4f 69 4d 5f 32 90 02 0c 20 2b 20 90 02 08 47 4b 4a 48 67 6b 68 67 4b 48 4a 47 6b 4f 69 4d 5f 33 90 00 } //01 00 
		$a_03_3 = {53 68 65 6c 6c 20 28 90 02 08 4d 5f 53 4f 69 4d 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_39{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 49 6d 61 67 65 6d 53 69 6d 70 6c 65 73 43 44 54 2c 20 4d 61 73 74 65 72 43 44 54 20 26 20 22 64 6f 63 75 6d 65 6e 74 2e 65 78 65 22 2c 20 30 2c 20 30 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 28 4d 5f 53 20 2b 20 54 4f 47 41 43 44 54 20 2b 20 4d 5f 53 31 20 2b 20 4d 5f 53 32 20 2b 20 4d 5f 53 33 29 } //01 00 
		$a_01_2 = {4d 61 73 74 65 72 43 44 54 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 } //01 00 
		$a_01_3 = {3d 20 22 3e 20 6e 75 6c 20 26 20 73 74 61 72 74 20 43 22 } //01 00 
		$a_01_4 = {50 44 66 5f 32 20 3d 20 22 65 78 65 22 22 20 2f 63 20 70 69 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_40{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 22 70 69 6e 67 2e 65 78 65 22 } //01 00 
		$a_01_1 = {3d 20 53 68 65 6c 6c 28 70 6f 74 61 6b 61 20 2b 20 70 6f 67 61 74 61 6c 6f 76 65 31 2c 20 76 62 4d 69 6e 69 6d 69 7a 65 64 46 6f 63 75 73 29 } //01 00 
		$a_01_2 = {3d 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 64 61 62 73 67 68 6b 64 74 61 37 73 64 74 61 73 67 76 6e 71 62 32 33 76 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_41{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 32 2e 6d 69 63 72 6f 73 6f 66 74 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 53 68 65 65 74 33 2e 6c 6f 6c 2c 20 53 68 65 65 74 31 2e 68 61 68 61 68 61 } //01 00 
		$a_01_1 = {3d 20 22 6d 73 68 74 61 22 } //01 00 
		$a_01_2 = {3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 61 73 64 61 73 64 66 77 66 66 64 77 6b 64 61 77 22 } //01 00 
		$a_01_3 = {3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 64 77 64 77 6b 64 61 64 6c 77 70 77 22 } //01 00 
		$a_01_4 = {3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 69 61 73 64 64 77 6b 6f 6b 6f 61 61 73 64 73 6b 64 61 77 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_42{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 6f 6b 6f 64 5f 78 77 6b 6f 6b 61 73 64 5f 57 64 6f 20 2b 20 61 53 44 4b 4b 5f 64 6d 77 6f 20 2b 20 6b 6f 6b 5f 64 61 6b 73 64 6f 20 2b 20 61 73 6b 64 6f 5f 57 78 6d 6f 20 2b 20 6b 6f 5f 64 77 6b 6f } //01 00 
		$a_01_1 = {3d 20 6c 6f 6c 6f 20 2b 20 6b 6f 6b 6f 20 2b 20 70 6c 70 6c 20 2b 20 70 6c 77 6f 20 2b 20 6c 61 64 70 73 6f 20 2b 20 68 75 70 70 70 20 2b 20 6b 6f 6b 6f 77 6f 6b 20 2b 20 6b 6f 6c 64 69 63 20 2b 20 70 75 74 6f 20 2b 20 6b 6f 6c 69 63 6c 63 20 2b 20 6b 6f 6c 69 63 6c 63 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 61 6c 69 29 2e 45 58 45 43 20 6c 6c 6c 20 2b 20 6c 6f 30 6f 6c } //01 00 
		$a_01_3 = {41 55 74 6f 5f 43 6c 4f 73 45 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_43{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 5f 0d 0a 20 20 28 30 2c 20 22 6f 70 65 6e 22 2c 20 6b 6f 6b 6f 2c 20 22 68 22 20 5f } //01 00 
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 5f 0d 0a 4c 69 62 20 5f 0d 0a 22 53 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 5f 0d 0a 41 6c 69 61 73 20 5f 0d 0a 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 5f } //01 00 
		$a_01_2 = {53 57 5f 53 48 4f 57 4d 69 6e 69 6d 69 7a 65 29 } //01 00 
		$a_01_3 = {22 25 70 75 62 6c 69 63 25 22 20 5f } //01 00 
		$a_01_4 = {6b 6f 6b 6f 20 5f 0d 0a 3d 20 5f 0d 0a 22 6d 22 20 5f 0d 0a 2b 20 5f 0d 0a 22 73 22 20 5f 0d 0a 2b 20 5f 0d 0a 22 68 22 20 5f 0d 0a 2b 20 5f 0d 0a 22 74 22 20 5f 0d 0a 2b 20 5f 0d 0a 22 61 22 0d 0a 45 6e 64 20 5f } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_44{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 72 65 67 77 72 69 74 65 20 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 73 65 78 2e 65 78 65 5c 22 2c 20 22 4d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 2c 20 22 52 45 47 5f 53 5a 22 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 22 73 65 78 20 68 74 74 70 73 3a 5c 5c 25 32 30 25 32 30 40 6a 2e 6d 70 5c 64 64 64 64 6a 78 64 73 61 64 61 73 64 61 73 69 64 6a 61 69 73 64 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_45{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 64 61 73 64 61 73 68 64 73 61 37 79 64 73 61 67 64 68 61 22 } //02 00 
		$a_01_1 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 64 61 73 64 36 37 61 73 65 68 6a 32 33 65 6e 61 73 64 5a 22 } //02 00 
		$a_01_2 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 73 36 61 37 73 61 67 68 67 61 68 73 32 73 64 78 7a 22 } //01 00 
		$a_01_3 = {53 68 65 6c 6c 20 22 70 69 6e 67 2e 65 78 65 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_46{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 3a 2f 2f 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 40 6a 2e 6d 22 } //03 00 
		$a_01_1 = {3d 20 70 75 62 69 74 69 74 79 36 20 2b 20 70 75 62 69 74 69 74 79 37 20 2b 20 70 75 62 69 74 69 74 79 38 20 2b 20 70 75 62 69 74 69 74 79 39 20 2b 20 22 70 2f 62 68 61 73 64 36 37 32 33 68 6a 61 73 76 64 62 6e 63 7a 76 78 63 6e 62 22 } //03 00 
		$a_01_2 = {3d 20 70 75 62 69 74 69 74 79 36 20 2b 20 70 75 62 69 74 69 74 79 37 20 2b 20 70 75 62 69 74 69 74 79 38 20 2b 20 70 75 62 69 74 69 74 79 39 20 2b 20 22 70 2f 62 63 6b 73 61 67 64 61 67 73 64 61 76 64 62 6e 7a 78 63 76 61 67 66 68 61 22 } //03 00 
		$a_01_3 = {3d 20 70 75 62 69 74 69 74 79 36 20 2b 20 70 75 62 69 74 69 74 79 37 20 2b 20 70 75 62 69 74 69 74 79 38 20 2b 20 70 75 62 69 74 69 74 79 39 20 2b 20 22 70 2f 67 62 6b 73 61 64 36 37 33 32 68 6a 67 62 63 7a 76 6e 7a 62 78 63 22 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 66 75 63 6b 7a 61 72 67 75 73 29 2e 45 78 65 63 20 72 65 73 6f 6e 73 77 68 79 31 30 20 2b 20 72 65 73 6f 6e 73 77 68 79 31 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_47{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 3a 2f 2f 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 40 6a 2e 6d 22 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 66 75 63 6b 7a 61 72 67 75 73 29 2e 45 78 65 63 20 72 65 73 6f 6e 73 77 68 79 31 30 20 2b 20 72 65 73 6f 6e 73 77 68 79 31 31 31 } //03 00 
		$a_01_2 = {3d 20 70 75 62 69 74 69 74 79 36 31 20 2b 20 70 75 62 69 74 69 74 79 37 31 20 2b 20 70 75 62 69 74 69 74 79 38 31 20 2b 20 70 75 62 69 74 69 74 79 39 31 20 2b 20 22 70 2f 67 64 6b 73 61 64 37 39 38 32 33 65 6b 61 6c 68 64 6b 6a 62 7a 78 63 22 } //03 00 
		$a_01_3 = {3d 20 70 75 62 69 74 69 74 79 36 31 20 2b 20 70 75 62 69 74 69 74 79 37 31 20 2b 20 70 75 62 69 74 69 74 79 38 31 20 2b 20 70 75 62 69 74 69 74 79 39 31 20 2b 20 22 70 2f 64 61 73 68 6b 64 36 37 61 65 32 68 67 33 65 6a 61 76 78 63 7a 6d 78 63 22 } //03 00 
		$a_01_4 = {3d 20 70 75 62 69 74 69 74 79 36 31 20 2b 20 70 75 62 69 74 69 74 79 37 31 20 2b 20 70 75 62 69 74 69 74 79 38 31 20 2b 20 70 75 62 69 74 69 74 79 39 31 20 2b 20 22 70 2f 64 31 61 32 73 33 64 61 73 64 68 67 6b 61 6a 64 74 33 65 32 67 68 6a 6b 61 73 64 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_48{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 22 70 69 6e 67 2e 65 78 65 22 } //01 00 
		$a_01_1 = {3d 20 53 68 65 6c 6c 28 6d 79 6c 6f 76 65 72 20 2b 20 70 61 72 6b 65 72 2c 20 76 62 4d 69 6e 69 6d 69 7a 65 64 46 6f 63 75 73 29 } //03 00 
		$a_01_2 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 37 39 38 32 33 34 67 68 73 64 62 6e 76 7a 68 67 64 66 79 73 41 42 4d 5a 4a 22 } //03 00 
		$a_01_3 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 61 68 6a 64 68 61 6b 73 64 61 73 64 62 68 6b 61 73 67 64 6a 68 22 } //03 00 
		$a_01_4 = {3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 61 64 76 73 62 64 61 73 68 64 66 6a 61 73 68 64 6c 61 6d 6e 78 7a 62 76 6e 61 62 66 73 64 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BPK_MTB_49{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 6a 64 77 77 61 73 6b 64 6f 72 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //01 00 
		$a_01_1 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 6a 64 77 77 64 77 64 77 64 6d 6c 72 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //01 00 
		$a_01_2 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 6a 64 77 77 64 77 64 72 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //01 00 
		$a_01_3 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 77 64 6f 77 64 70 6b 64 6f 77 64 77 70 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //01 00 
		$a_01_4 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 77 64 6f 77 64 70 6f 77 64 6c 77 64 70 72 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //01 00 
		$a_01_5 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 77 64 64 77 64 77 6f 64 6b 70 64 6c 77 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //01 00 
		$a_01_6 = {4d 73 67 42 6f 78 20 22 45 72 72 6f 72 21 21 22 } //00 00 
	condition:
		any of ($a_*)
 
}