
rule TrojanDownloader_O97M_Malgent_A{
	meta:
		description = "TrojanDownloader:O97M/Malgent.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 44 65 73 6b 74 6f 70 22 20 26 20 22 5c 71 75 6f 74 61 74 69 6f 6e 2e 65 78 65 22 0d 0a 53 68 65 6c 6c 20 28 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 34 35 2e 37 38 2e 32 31 2e 31 35 30 2f 62 6f 6f 73 74 2f 62 6f 6f 73 74 69 6e 67 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}