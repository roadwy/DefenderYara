
rule TrojanDownloader_O97M_EncDoc_I_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.I!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 6d 61 72 63 68 32 36 32 30 32 30 2e 63 6c 75 62 2f 66 69 6c 65 73 2f 90 02 10 2e 64 6c 6c 90 00 } //01 00 
		$a_01_1 = {43 3a 5c 58 54 48 62 53 4a 58 5c 68 51 50 44 70 51 6d 5c 79 4e 75 4d 79 44 63 2e 64 6c } //01 00  C:\XTHbSJX\hQPDpQm\yNuMyDc.dl
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}