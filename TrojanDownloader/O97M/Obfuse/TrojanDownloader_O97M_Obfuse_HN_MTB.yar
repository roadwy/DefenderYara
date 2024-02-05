
rule TrojanDownloader_O97M_Obfuse_HN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 55 52 20 3d 20 22 68 74 74 70 3a 2f 2f 35 34 2e 33 39 2e 32 33 33 2e 31 33 30 2f 64 65 33 2e 74 6d 70 22 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 66 50 54 28 } //01 00 
		$a_01_2 = {26 20 22 2e 65 22 20 26 20 22 78 65 22 } //00 00 
	condition:
		any of ($a_*)
 
}