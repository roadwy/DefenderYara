
rule TrojanDownloader_O97M_Lyantiq_A{
	meta:
		description = "TrojanDownloader:O97M/Lyantiq.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 6c 6f 76 65 6c 79 61 6e 74 69 71 75 65 73 2e 69 6e 66 6f 2f 62 69 6e 2f 69 6e 76 2e 65 78 65 } //00 00  http://lovelyantiques.info/bin/inv.exe
	condition:
		any of ($a_*)
 
}