
rule TrojanSpy_AndroidOS_SMSZombie_B_xp{
	meta:
		description = "TrojanSpy:AndroidOS/SMSZombie.B!xp,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 43 54 49 4f 49 4e 5f 53 45 4e 44 5f 53 4d 53 5f 42 55 59 } //01 00  ACTIOIN_SEND_SMS_BUY
		$a_00_1 = {53 45 4e 44 5f 53 4d 53 5f 4e 55 4d } //01 00  SEND_SMS_NUM
		$a_00_2 = {6c 69 62 6b 6a 4f 6e 6c 69 6e 65 50 61 79 2e 73 6f } //01 00  libkjOnlinePay.so
		$a_00_3 = {2f 77 6d 61 70 70 2f 57 4d 41 70 70 49 6e 69 74 } //00 00  /wmapp/WMAppInit
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}