
rule Trojan_AndroidOS_FakeInstSms_JA{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.JA,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 45 4e 44 45 44 5f 53 4d 53 5f 43 4f 55 4e 54 45 52 5f 4b 45 59 } //01 00  SENDED_SMS_COUNTER_KEY
		$a_01_1 = {50 41 59 45 44 5f 4b 45 59 } //01 00  PAYED_KEY
		$a_01_2 = {53 4d 53 5f 44 41 54 41 5f 4b 45 59 } //01 00  SMS_DATA_KEY
		$a_01_3 = {63 6f 6d 2e 73 6f 66 74 77 61 72 65 2e 61 6e 64 72 6f 69 64 2e 69 6e 73 74 61 6c 6c 2e 70 65 72 6d 69 73 73 69 6f 6e 2e 43 32 44 5f 4d 45 53 53 41 47 45 } //00 00  com.software.android.install.permission.C2D_MESSAGE
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}