
rule TrojanDownloader_O97M_Emotet_EMPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.EMPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 78 70 72 6f 73 61 63 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 55 6c 6f 75 39 57 48 55 6a 55 6b 43 4a 43 7a 68 30 63 56 31 2f } //01 00 
		$a_01_1 = {2f 77 6f 6c 6c 65 2e 70 6c 2f 31 30 30 30 30 2f 70 4b 39 32 4b 38 6d 7a 73 55 68 49 78 4e 48 37 74 2f } //01 00 
		$a_01_2 = {2f 2f 72 65 74 61 72 64 61 6e 74 65 64 65 66 75 65 67 6f 70 65 72 75 2e 63 6f 6d 2f 73 6c 69 64 65 72 2f 45 33 61 6f 64 2f } //01 00 
		$a_01_3 = {2f 2f 78 65 76 69 73 2e 6e 65 74 2f 78 65 76 69 73 2f 74 49 6b 5a 6b 57 48 2f } //00 00 
	condition:
		any of ($a_*)
 
}