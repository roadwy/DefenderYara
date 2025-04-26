
rule TrojanDownloader_O97M_EncDoc_RPQ0212_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RPQ0212!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2e 74 65 78 74 3d 22 63 [0-0a] 6d 64 2f 90 1b 00 63 73 90 1b 00 74 61 72 90 1b 00 74 2f 90 1b 00 62 22 [0-1f] 2e [0-5f] 90 1b 05 [0-1f] 3d 72 65 70 6c 61 63 65 28 90 1b 05 2e [0-1f] 2c 22 90 1b 00 22 2c 22 22 29 6f 70 65 6e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}