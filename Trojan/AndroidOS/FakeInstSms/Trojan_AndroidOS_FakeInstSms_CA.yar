
rule Trojan_AndroidOS_FakeInstSms_CA{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.CA,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 73 6f 66 74 2f 61 6e 64 72 6f 69 64 2f 61 70 70 69 6e 73 74 61 6c 6c 65 72 2f 73 6d 73 2f 42 69 6e 61 72 79 53 4d 53 52 65 63 65 69 76 65 72 } //01 00  Lcom/soft/android/appinstaller/sms/BinarySMSReceiver
		$a_00_1 = {67 65 74 44 63 53 6d 73 43 6f 75 6e 74 } //01 00  getDcSmsCount
		$a_00_2 = {55 6e 63 6f 6e 66 69 72 6d 61 62 6c 65 53 4d 53 53 65 6e 64 65 72 45 6e 67 69 6e 65 49 6d 70 6c } //01 00  UnconfirmableSMSSenderEngineImpl
		$a_00_3 = {65 78 70 65 63 74 65 64 4d 6f 6e 65 79 52 65 73 74 } //01 00  expectedMoneyRest
		$a_00_4 = {53 6d 73 49 6e 66 6f 28 29 20 43 2d 74 6f 72 } //00 00  SmsInfo() C-tor
		$a_00_5 = {5d 04 00 } //00 46 
	condition:
		any of ($a_*)
 
}