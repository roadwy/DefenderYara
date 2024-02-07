
rule Trojan_AndroidOS_Fakecalls_B{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.B,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 43 54 49 4f 4e 5f 53 45 4e 44 5f 44 41 54 41 } //02 00  ACTION_SEND_DATA
		$a_00_1 = {47 45 54 5f 4c 49 4d 49 54 5f 50 48 4f 4e 45 5f 4e 55 4d 42 45 52 } //02 00  GET_LIMIT_PHONE_NUMBER
		$a_00_2 = {41 4c 4c 5f 50 45 52 4d 49 53 53 49 4f 4e } //02 00  ALL_PERMISSION
		$a_00_3 = {49 27 6d 20 62 75 73 79 20 65 6e 6f 75 67 68 } //02 00  I'm busy enough
		$a_00_4 = {43 72 6f 70 59 75 76 } //00 00  CropYuv
	condition:
		any of ($a_*)
 
}