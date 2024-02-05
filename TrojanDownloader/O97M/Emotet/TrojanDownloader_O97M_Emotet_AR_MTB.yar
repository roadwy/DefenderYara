
rule TrojanDownloader_O97M_Emotet_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {65 78 65 05 00 00 55 52 4c 44 6f 01 00 00 44 01 00 00 73 08 00 00 64 54 6f 46 69 6c 65 41 05 00 00 77 6e 6c 6f 61 04 00 00 6c 4d 6f 6e 06 00 00 4a 4a 43 43 4a 4a } //00 00 
	condition:
		any of ($a_*)
 
}