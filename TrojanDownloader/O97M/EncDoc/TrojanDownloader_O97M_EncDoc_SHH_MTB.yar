
rule TrojanDownloader_O97M_EncDoc_SHH_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SHH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00 
		$a_01_1 = {3d 20 22 22 22 65 78 65 2e 38 39 30 35 37 30 30 32 25 52 45 44 52 4f 2f 6c 6c 78 64 2f 6d 6f 63 2e 6d 61 6b 63 69 6c 63 74 73 75 6a 2f 2f 3a 73 70 74 74 68 22 22 22 } //00 00 
	condition:
		any of ($a_*)
 
}