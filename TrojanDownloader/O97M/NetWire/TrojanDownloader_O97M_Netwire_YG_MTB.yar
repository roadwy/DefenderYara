
rule TrojanDownloader_O97M_Netwire_YG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Netwire.YG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 27 2b 27 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 64 66 51 42 55 59 63 } //01 00 
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 20 68 20 49 60 77 52 } //01 00 
		$a_01_2 = {2d 4f 75 74 46 69 6c 65 20 28 27 74 65 73 74 35 27 2b 27 2e 65 78 65 27 29 } //00 00 
	condition:
		any of ($a_*)
 
}