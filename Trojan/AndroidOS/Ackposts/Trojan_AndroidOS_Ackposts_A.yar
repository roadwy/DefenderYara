
rule Trojan_AndroidOS_Ackposts_A{
	meta:
		description = "Trojan:AndroidOS/Ackposts.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {69 51 75 65 72 79 4d 69 73 73 4f 72 64 65 72 43 61 6c 6c 62 61 63 6b } //02 00  iQueryMissOrderCallback
		$a_01_1 = {76 33 66 6d 68 72 70 31 35 } //00 00  v3fmhrp15
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Ackposts_A_2{
	meta:
		description = "Trojan:AndroidOS/Ackposts.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 61 63 6b 70 6f 73 74 73 73 73 2e 68 65 74 65 6d 6c 2e 6a 70 2f 62 61 74 74 65 72 79 6c 6f 6e 67 2e 70 68 70 } //01 00  jackpostsss.heteml.jp/batterylong.php
		$a_01_1 = {68 61 73 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //01 00  has_phone_number
		$a_01_2 = {63 6f 6e 74 61 63 74 5f 69 64 20 3d 20 3f } //01 00  contact_id = ?
		$a_01_3 = {43 6f 6d 6d 6f 6e 44 61 74 61 4b 69 6e 64 73 24 45 6d 61 69 6c } //00 00  CommonDataKinds$Email
	condition:
		any of ($a_*)
 
}