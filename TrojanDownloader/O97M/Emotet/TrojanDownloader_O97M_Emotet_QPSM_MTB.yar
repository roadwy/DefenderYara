
rule TrojanDownloader_O97M_Emotet_QPSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QPSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 65 6f 65 78 63 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 67 4f 54 65 46 6d 4d 75 58 68 66 73 47 71 44 6c 2f } //01 00  neoexc.com/cgi-bin/gOTeFmMuXhfsGqDl/
		$a_01_1 = {6d 79 74 68 69 63 70 65 61 6b 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 7a 47 57 51 39 71 33 51 73 57 55 2f } //01 00  mythicpeak.com/wp-includes/zGWQ9q3QsWU/
		$a_01_2 = {64 65 6d 6f 2d 72 65 2d 75 73 61 62 6c 65 73 2e 69 6e 65 72 74 69 61 73 6f 66 74 2e 6e 65 74 2f 63 67 69 2d 62 69 6e 2f 7a 31 43 44 2f } //01 00  demo-re-usables.inertiasoft.net/cgi-bin/z1CD/
		$a_01_3 = {6d 75 68 73 69 6e 73 69 72 69 6d 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 56 74 32 75 6d 76 71 33 75 66 79 42 5a 5a 57 52 32 48 5a 2f } //00 00  muhsinsirim.com/cgi-bin/Vt2umvq3ufyBZZWR2HZ/
	condition:
		any of ($a_*)
 
}