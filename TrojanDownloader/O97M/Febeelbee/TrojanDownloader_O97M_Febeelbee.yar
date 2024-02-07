
rule TrojanDownloader_O97M_Febeelbee{
	meta:
		description = "TrojanDownloader:O97M/Febeelbee,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 69 74 2e 64 6f 2f 62 65 65 62 65 65 31 31 66 65 62 } //01 00  http://bit.do/beebee11feb
		$a_01_1 = {5c 73 6f 6d 6d 2e 65 78 65 } //00 00  \somm.exe
	condition:
		any of ($a_*)
 
}