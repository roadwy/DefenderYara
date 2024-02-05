
rule TrojanDownloader_O97M_EncDoc_KAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 62 76 2e 74 6e 65 69 6c 43 30 32 25 64 65 74 63 65 74 6f 72 50 2f 32 2f 7a 69 62 2e 72 65 6d 61 65 64 2f 2f 3a } //00 00 
	condition:
		any of ($a_*)
 
}