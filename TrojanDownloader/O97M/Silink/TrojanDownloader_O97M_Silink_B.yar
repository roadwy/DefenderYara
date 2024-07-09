
rule TrojanDownloader_O97M_Silink_B{
	meta:
		description = "TrojanDownloader:O97M/Silink.B,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c 6c 20 28 22 6d 73 68 74 61 20 68 74 74 70 73 3a 2f 2f 6c 6f 67 69 6e 2d 6d 61 69 6e 2e 62 69 67 77 6e 65 74 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 2f 76 69 65 77 2f 4d 73 67 [0-03] 2e 68 74 61 22 29 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}