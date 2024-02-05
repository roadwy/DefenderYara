
rule TrojanDownloader_O97M_Ursnif_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 50 5e 22 20 2b 20 43 68 72 28 90 10 03 00 20 2b 20 90 10 03 00 20 2b 20 28 90 10 03 00 29 20 2b 20 90 10 03 00 29 20 2b 20 22 5e 57 5e 65 5e 72 5e 73 5e 22 20 2b 20 43 68 72 28 90 10 03 00 20 2b 20 28 90 10 03 00 20 2a 20 90 10 03 00 29 29 20 2b 20 22 5e 65 5e 4c 5e 4c 5e 2e 5e 65 5e 78 5e 65 5e 20 5e 2d 5e 45 5e 43 5e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}