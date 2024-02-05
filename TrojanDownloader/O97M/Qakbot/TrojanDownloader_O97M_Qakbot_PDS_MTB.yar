
rule TrojanDownloader_O97M_Qakbot_PDS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 49 6d 63 68 74 72 69 61 5c 4e 69 74 75 62 73 72 74 61 5c 90 02 0a 6e 73 65 62 2e 4f 4f 4f 4f 4f 43 43 43 43 43 58 58 58 58 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}