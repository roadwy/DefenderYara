
rule TrojanDownloader_O97M_Obfuse_PAV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 79 6e 65 72 67 79 63 74 73 66 6c 2e 63 6f 6d 2f 66 61 6c 63 6f 6e 2e 65 78 65 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_00_2 = {67 69 66 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}