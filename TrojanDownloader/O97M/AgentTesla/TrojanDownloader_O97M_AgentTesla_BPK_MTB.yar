
rule TrojanDownloader_O97M_AgentTesla_BPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 6e 70 6f 77 65 72 31 20 3d 20 6d 61 6e 31 20 2b 20 6d 61 6e 32 20 2b 20 6d 61 6e 33 } //01 00 
		$a_01_1 = {44 65 62 75 67 2e 41 73 73 65 72 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 6d 61 6e 70 6f 77 65 72 33 29 29 } //01 00 
		$a_01_2 = {6d 61 6e 32 20 3d 20 69 63 65 63 72 65 61 6d 31 2e 6a 61 63 6b 31 2e 54 61 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_AgentTesla_BPK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 6b 2e 6d 79 76 61 6c 75 65 20 2b 20 6b 2e 6d 79 76 61 6c 75 65 32 } //01 00 
		$a_01_1 = {74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 2e 6a 2e 6d 70 2f 61 73 64 61 6b 73 64 6a 71 77 6f 64 64 61 73 6b 64 61 6a 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_AgentTesla_BPK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 20 48 22 20 2b 20 44 20 2b 20 44 20 2b 20 4c 20 2b 20 22 3a 2f 2f 22 20 2b 20 4b 20 2b 20 54 } //01 00 
		$a_01_1 = {70 69 6e 67 73 20 3d 20 58 20 2b 20 59 20 2b 20 5a 20 2b 20 44 20 2b 20 45 20 2b 20 46 } //01 00 
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42 22 29 2e 45 58 45 43 20 70 69 6e 67 73 } //01 00 
		$a_01_3 = {3d 20 22 61 73 64 69 6d 61 77 78 69 77 6d 61 77 69 64 77 77 64 6b 69 69 77 6e 61 77 69 6a 22 } //00 00 
	condition:
		any of ($a_*)
 
}