
rule Trojan_AndroidOS_Koler_BL_MTB{
	meta:
		description = "Trojan:AndroidOS/Koler.BL!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 5f 69 64 65 6e 74 69 66 69 63 61 74 69 6f 6e 67 65 6f 5f 63 6f 6d 5f 74 6f 70 6e 65 77 73 5f 6e 65 77 5f 64 5f 70 68 70 5f 69 64 5f } //02 00  http_identificationgeo_com_topnews_new_d_php_id_
		$a_00_1 = {66 69 6c 65 5f 61 6e 64 72 6f 69 64 5f 61 73 73 65 74 5f 69 6e 64 65 78 5f 68 74 6d 6c } //01 00  file_android_asset_index_html
		$a_00_2 = {69 73 4d 79 53 65 72 76 69 63 65 52 75 6e 6e 69 6e 67 } //01 00  isMyServiceRunning
		$a_00_3 = {68 69 64 65 61 6c 6c } //01 00  hideall
		$a_00_4 = {73 65 6e 64 5f 74 6f 5f } //00 00  send_to_
	condition:
		any of ($a_*)
 
}