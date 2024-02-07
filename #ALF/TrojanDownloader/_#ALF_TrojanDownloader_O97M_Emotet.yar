
rule _#ALF_TrojanDownloader_O97M_Emotet{
	meta:
		description = "!#ALF:TrojanDownloader:O97M/Emotet,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 90 02 10 22 0d 0a 53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 0d 0a 20 20 20 44 69 6d 20 90 00 } //01 00 
		$a_01_1 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 54 72 75 65 20 41 6e 64 20 46 61 6c 73 65 } //01 00  .ShowWindow = True And False
		$a_03_2 = {2e 43 61 70 74 69 6f 6e 20 2b 20 90 02 10 2e 90 02 10 2e 43 61 70 74 69 6f 6e 29 29 29 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 71 
	condition:
		any of ($a_*)
 
}