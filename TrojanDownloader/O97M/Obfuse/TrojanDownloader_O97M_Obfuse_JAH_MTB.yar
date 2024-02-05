
rule TrojanDownloader_O97M_Obfuse_JAH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 65 6e 67 69 6e 6f 74 65 6c 66 69 6e 69 6b 65 2e 63 6f 6d 2f 31 39 2e 67 69 66 } //02 00 
		$a_01_1 = {43 3a 5c 57 45 72 74 75 5c 52 65 74 65 72 64 5c 73 7a 76 6d 68 65 67 75 2e 65 78 65 } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}