
rule TrojanDownloader_O97M_Otcontavir{
	meta:
		description = "TrojanDownloader:O97M/Otcontavir,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 68 74 22 20 26 20 22 74 70 3a 22 20 26 20 22 2f 22 20 26 20 22 2f 22 20 26 20 22 73 75 63 22 20 26 20 22 65 73 6f 72 65 73 2e 63 6f 6d 2e 6d 22 20 26 20 22 78 2f 69 6d 61 67 65 73 2f 6c 6f 22 20 26 20 22 67 6f 2e 67 22 20 26 20 22 69 66 22 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 75 63 65 73 6f 72 65 73 2e 63 6f 6d 2e 6d 78 2f 69 6d 61 67 65 73 2f 6c 6f 67 6f 2e 67 69 66 } //00 00 
	condition:
		any of ($a_*)
 
}