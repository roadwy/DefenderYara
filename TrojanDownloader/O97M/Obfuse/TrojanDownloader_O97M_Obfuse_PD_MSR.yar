
rule TrojanDownloader_O97M_Obfuse_PD_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PD!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 90 02 10 4a 4a 43 43 4a 4a 90 02 10 68 74 74 70 90 02 02 3a 2f 2f 67 32 63 72 65 64 69 74 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f 74 72 75 73 74 79 2f 90 02 20 2e 70 6e 67 90 02 10 63 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 31 2e 65 78 65 90 00 } //01 00 
		$a_02_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 90 02 10 4a 4a 43 43 4a 4a 90 02 10 68 74 74 70 90 02 02 3a 2f 2f 6c 6f 72 72 61 69 6e 65 68 6f 6d 65 63 6f 6e 73 75 6c 74 69 6e 67 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 90 02 20 2f 74 72 75 73 74 79 2f 90 02 10 2e 70 6e 67 90 02 05 63 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 31 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}