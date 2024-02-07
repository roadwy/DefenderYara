
rule TrojanDownloader_O97M_Emotet_SKPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SKPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 62 75 66 66 65 74 6d 61 7a 7a 69 2e 63 6f 6d 2e 62 72 2f 63 6b 66 69 6e 64 65 72 2f 75 72 68 68 51 63 35 57 2f } //01 00  //buffetmazzi.com.br/ckfinder/urhhQc5W/
		$a_01_1 = {2f 2f 77 77 77 2e 7a 69 67 6f 72 61 74 2e 75 73 2f 77 70 2d 61 64 6d 69 6e 2f 67 55 45 4d 6d 44 76 6e 6c 2f } //01 00  //www.zigorat.us/wp-admin/gUEMmDvnl/
		$a_01_2 = {2f 2f 77 77 77 2e 63 65 73 61 73 69 6e 2e 63 6f 6d 2e 61 72 2f 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 2f 56 4e 74 7a 5a 56 56 54 41 4a 4e 48 37 2f } //01 00  //www.cesasin.com.ar/administrator/VNtzZVVTAJNH7/
		$a_01_3 = {2f 2f 77 65 68 78 2e 63 6f 6d 2e 62 72 2f 77 70 2d 73 6e 61 70 73 68 6f 74 73 2f 64 73 33 37 4c 56 4c 2f } //00 00  //wehx.com.br/wp-snapshots/ds37LVL/
	condition:
		any of ($a_*)
 
}