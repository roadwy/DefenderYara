
rule TrojanDownloader_O97M_Iseriste_A{
	meta:
		description = "TrojanDownloader:O97M/Iseriste.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {2b 20 22 50 72 6f 63 65 73 73 20 27 25 54 4d 50 25 5c 74 65 72 6f 72 69 73 74 2e 65 78 65 27 3b 22 } //00 00 
	condition:
		any of ($a_*)
 
}