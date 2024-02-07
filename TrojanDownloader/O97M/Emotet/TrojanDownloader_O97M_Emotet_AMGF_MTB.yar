
rule TrojanDownloader_O97M_Emotet_AMGF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMGF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 90 02 0f 5c 90 02 0f 2e 6f 63 78 42 90 00 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}