
rule TrojanDownloader_O97M_Obfuse_PAL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 6c 6f 67 2e 76 6f 6b 61 73 69 64 65 76 2e 63 6f 6d 2f 63 72 75 6e 32 30 2e 67 69 66 } //04 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 6a 61 62 62 61 2e 66 75 6e 2f 63 72 75 6e 32 30 2e 67 69 66 } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_03_3 = {43 3a 5c 43 4f 73 75 76 5c 90 02 10 5c 90 02 15 2e 65 78 65 90 00 } //01 00 
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}