
rule Trojan_AndroidOS_Lozfoon_A{
	meta:
		description = "Trojan:AndroidOS/Lozfoon.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 70 70 6c 69 2f 61 64 64 72 65 73 73 42 6f 6f 6b 52 65 67 69 73 74 } //01 00  appli/addressBookRegist
		$a_01_1 = {41 50 50 4c 49 5f 4d 41 49 4c 5f 44 49 56 5f 50 41 52 41 4d } //01 00  APPLI_MAIL_DIV_PARAM
		$a_01_2 = {23 23 61 64 64 72 65 73 73 4e 61 6d 65 23 23 } //01 00  ##addressName##
		$a_01_3 = {63 6f 6e 74 61 63 74 5f 6d 65 74 68 6f 64 73 2e 5f 69 64 20 3d 20 3f } //00 00  contact_methods._id = ?
	condition:
		any of ($a_*)
 
}