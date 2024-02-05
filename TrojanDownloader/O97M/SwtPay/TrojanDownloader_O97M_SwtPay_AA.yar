
rule TrojanDownloader_O97M_SwtPay_AA{
	meta:
		description = "TrojanDownloader:O97M/SwtPay.AA,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 44 6f 77 6e 4c 6f 41 64 66 49 6c 45 28 90 02 20 94 68 74 74 70 3a 2f 2f 61 6c 6b 75 74 65 63 68 73 6c 6c 63 2e 63 6f 6d 2f 90 02 20 2f 90 02 20 2e 65 78 65 94 90 00 } //01 00 
		$a_03_1 = {24 45 4e 76 3a 74 65 4d 70 5c 90 02 20 2e 65 78 65 90 00 } //01 00 
		$a_03_2 = {73 74 41 52 74 2d 50 52 6f 43 45 53 73 20 94 24 45 4e 76 3a 74 45 4d 50 5c 90 02 20 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}