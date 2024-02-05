
rule TrojanDownloader_O97M_Donoff_STLV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.STLV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 22 68 74 74 70 3a 2f 2f 31 39 32 2e 32 31 30 2e 31 34 39 2e 32 34 32 2f 6d 61 63 2e 74 78 74 22 29 } //01 00 
		$a_01_1 = {46 56 76 51 64 57 2e 45 78 65 63 28 77 70 6c 6d 57 28 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}