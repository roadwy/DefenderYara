
rule TrojanDownloader_O97M_Obfuse_HQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00 
		$a_03_1 = {53 65 74 20 90 02 12 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 90 02 10 29 90 00 } //01 00 
		$a_03_2 = {29 2e 52 75 6e 21 20 90 02 14 2c 20 32 20 2b 90 00 } //01 00 
		$a_01_3 = {2e 43 6f 6e 74 72 6f 6c 73 } //01 00 
		$a_01_4 = {2e 56 61 6c 75 65 } //00 00 
	condition:
		any of ($a_*)
 
}