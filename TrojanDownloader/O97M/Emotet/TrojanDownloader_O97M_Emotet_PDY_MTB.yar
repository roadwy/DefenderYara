
rule TrojanDownloader_O97M_Emotet_PDY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 61 70 69 2e 7a 6d 6f 74 70 72 6f 2e 63 6f 6d 2f 74 6f 74 61 6c 65 6e 76 69 72 6f 6e 6d 65 6e 74 2f 6c 6f 67 73 2f 38 77 64 67 4e 61 71 30 78 2f } //01 00  ://api.zmotpro.com/totalenvironment/logs/8wdgNaq0x/
		$a_01_1 = {3a 2f 2f 61 65 74 6f 61 6c 75 6d 69 6e 69 75 6d 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 67 6b 71 79 4b 6c 7a 58 6f 63 2f } //01 00  ://aetoaluminium.com/wp-admin/gkqyKlzXoc/
		$a_01_2 = {3a 2f 2f 32 34 73 74 75 64 79 70 6f 69 6e 74 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 33 75 45 55 74 62 2f } //01 00  ://24studypoint.com/wp-admin/3uEUtb/
		$a_01_3 = {3a 2f 2f 62 61 69 63 63 2d 63 74 2e 6f 72 67 2f 77 70 2d 61 64 6d 69 6e 2f 49 77 68 63 66 43 32 73 64 78 6f 54 6f 61 2f } //01 00  ://baicc-ct.org/wp-admin/IwhcfC2sdxoToa/
		$a_01_4 = {3a 2f 2f 6d 75 73 74 6b 6e 65 77 2e 63 6f 6d 2f 6c 6f 76 65 63 61 6c 63 75 6c 61 74 6f 72 2f 6f 73 44 42 68 50 71 78 30 74 42 31 56 74 70 2f } //01 00  ://mustknew.com/lovecalculator/osDBhPqx0tB1Vtp/
		$a_01_5 = {3a 2f 2f 6b 69 73 6b 69 30 32 33 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 52 65 71 75 65 73 74 73 2f 43 6f 6f 6b 69 65 2f 43 2f } //00 00  ://kiski023.com/wp-includes/Requests/Cookie/C/
	condition:
		any of ($a_*)
 
}