
rule TrojanDownloader_O97M_Obfuse_PV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 20 3d 20 22 50 72 6f 6a 65 63 74 2e 4d 61 63 72 6f 42 6c 65 2e 41 75 74 6f 4f 70 65 6e 22 } //01 00 
		$a_00_1 = {2e 53 61 76 65 41 73 20 28 47 65 74 50 61 74 68 24 20 2b 20 22 4e 4f 52 4d 41 4c 31 2e 44 4f 54 22 29 } //01 00 
		$a_00_2 = {27 4d 73 67 42 6f 78 20 22 46 75 63 6b 20 75 70 20 21 } //00 00 
	condition:
		any of ($a_*)
 
}