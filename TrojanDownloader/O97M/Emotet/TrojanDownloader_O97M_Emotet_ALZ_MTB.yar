
rule TrojanDownloader_O97M_Emotet_ALZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ALZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 75 78 65 76 72 31 2e 6f 63 78 } //01 00  \uxevr1.ocx
		$a_01_1 = {5c 75 78 65 76 72 32 2e 6f 63 78 } //01 00  \uxevr2.ocx
		$a_01_2 = {5c 75 78 65 76 72 33 2e 6f 63 78 } //01 00  \uxevr3.ocx
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}