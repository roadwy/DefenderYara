
rule Trojan_AndroidOS_Piom_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Piom.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 74 65 73 74 5f 61 70 70 2f 41 75 74 6f 53 74 61 72 74 53 65 72 76 69 63 65 5f 68 6f 67 69 } //01 00  com/android/test_app/AutoStartService_hogi
		$a_01_1 = {63 61 6c 6c 73 5f 61 6c 6c 5f 73 65 6e 74 } //01 00  calls_all_sent
		$a_01_2 = {44 41 54 41 5f 61 70 70 5f 61 6c 65 72 74 } //01 00  DATA_app_alert
		$a_01_3 = {3c 3e 73 6d 73 5f 61 70 70 } //01 00  <>sms_app
		$a_01_4 = {73 65 72 76 65 72 34 35 35 34 69 63 2e 68 65 72 6f 6b 75 61 70 70 2e 63 6f 6d } //01 00  server4554ic.herokuapp.com
		$a_01_5 = {61 6c 6c 5f 73 6d 73 5f 72 65 63 65 69 76 65 64 } //01 00  all_sms_received
		$a_01_6 = {61 6c 6c 5f 63 61 6c 6c 5f 72 65 63 65 69 76 65 64 } //00 00  all_call_received
		$a_00_7 = {5d 04 00 00 } //5b 2b 
	condition:
		any of ($a_*)
 
}