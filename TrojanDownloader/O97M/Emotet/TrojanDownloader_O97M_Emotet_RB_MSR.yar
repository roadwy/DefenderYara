
rule TrojanDownloader_O97M_Emotet_RB_MSR{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RB!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //01 00 
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 62 75 69 6c 64 69 6e 67 73 61 6e 64 70 6f 6f 6c 73 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 69 79 36 75 78 36 31 33 32 36 30 } //00 00 
	condition:
		any of ($a_*)
 
}