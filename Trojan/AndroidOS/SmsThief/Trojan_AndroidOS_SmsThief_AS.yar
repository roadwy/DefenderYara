
rule Trojan_AndroidOS_SmsThief_AS{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AS,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {6e 61 76 69 67 61 74 65 54 6f 4d 61 69 6e 41 63 74 69 76 69 74 79 49 66 50 65 72 6d 69 73 73 69 6f 6e 73 47 72 61 6e 74 65 64 } //02 00  navigateToMainActivityIfPermissionsGranted
		$a_01_1 = {61 75 74 68 2f 61 64 6d 69 6e 5f 69 6e 66 6f 2f 6e 75 6d 62 65 72 } //00 00  auth/admin_info/number
	condition:
		any of ($a_*)
 
}