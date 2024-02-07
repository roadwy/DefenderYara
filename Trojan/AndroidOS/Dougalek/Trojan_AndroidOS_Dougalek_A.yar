
rule Trojan_AndroidOS_Dougalek_A{
	meta:
		description = "Trojan:AndroidOS/Dougalek.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 75 67 61 } //01 00  douga
		$a_03_1 = {68 74 74 70 3a 2f 2f 64 65 70 6f 74 2e 62 75 6c 6b 73 2e 6a 70 2f 67 65 74 90 01 02 2e 70 68 70 90 00 } //01 00 
		$a_01_2 = {63 6f 6e 74 61 63 74 5f 69 64 20 3d } //01 00  contact_id =
		$a_01_3 = {68 74 74 70 5f 70 6f 73 74 5f 73 75 63 63 65 73 73 } //01 00  http_post_success
		$a_01_4 = {74 65 6d 70 5f 74 65 78 74 } //00 00  temp_text
	condition:
		any of ($a_*)
 
}