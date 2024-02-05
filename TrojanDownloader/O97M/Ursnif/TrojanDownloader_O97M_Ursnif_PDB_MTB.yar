
rule TrojanDownloader_O97M_Ursnif_PDB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 74 79 20 26 20 22 2e 22 } //01 00 
		$a_01_1 = {3d 20 53 70 6c 69 74 28 52 61 6e 67 65 28 22 49 37 39 3a 49 37 39 22 29 2c 20 22 2c 22 29 } //01 00 
		$a_01_2 = {3d 20 48 69 69 4a 69 69 28 22 22 20 26 20 76 53 78 65 65 44 29 3a } //01 00 
		$a_01_3 = {3d 20 45 72 6a 4f 6b 69 28 44 44 2c 20 44 53 77 29 } //01 00 
		$a_01_4 = {3d 20 42 6e 3a 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 51 75 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}