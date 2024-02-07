
rule Trojan_AndroidOS_Dougalek_C{
	meta:
		description = "Trojan:AndroidOS/Dougalek.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 65 70 6f 74 2e 62 75 6c 6b 73 2e 6a 70 2f 67 65 74 90 01 02 2e 70 68 70 90 00 } //01 00 
		$a_01_1 = {63 6f 6e 74 61 63 74 5f 69 64 20 3d } //01 00  contact_id =
		$a_01_2 = {68 74 74 70 5f 70 6f 73 74 5f 73 75 63 63 65 73 73 } //01 00  http_post_success
		$a_01_3 = {75 61 75 73 5f 66 65 69 6a } //00 00  uaus_feij
	condition:
		any of ($a_*)
 
}