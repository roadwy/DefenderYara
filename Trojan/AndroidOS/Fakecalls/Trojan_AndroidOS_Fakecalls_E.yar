
rule Trojan_AndroidOS_Fakecalls_E{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.E,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 6f 72 77 61 72 64 69 6e 67 53 68 6f 77 50 68 6f 6e 65 3a } //02 00  forwardingShowPhone:
		$a_01_1 = {53 75 63 63 65 73 73 20 74 6f 20 75 70 6c 6f 61 64 20 63 61 6c 6c 6f 67 } //02 00  Success to upload callog
		$a_01_2 = {4b 45 59 5f 49 53 5f 46 4f 52 57 41 52 44 49 4e 47 5f 48 41 4e 44 5f 55 50 } //02 00  KEY_IS_FORWARDING_HAND_UP
		$a_01_3 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 46 69 6c 65 } //00 00  uploadCallLogFile
	condition:
		any of ($a_*)
 
}