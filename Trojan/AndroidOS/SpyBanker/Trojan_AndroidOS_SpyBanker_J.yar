
rule Trojan_AndroidOS_SpyBanker_J{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.J,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 73 72 74 68 6b 2f 70 74 68 6b 2f 73 6d 73 66 6f 72 77 61 72 64 65 72 2f 73 65 72 76 69 63 65 73 } //01 00  Lsrthk/pthk/smsforwarder/services
		$a_01_1 = {52 45 51 5f 43 4f 44 45 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 53 45 4e 44 5f 53 4d 53 } //01 00  REQ_CODE_PERMISSION_SEND_SMS
		$a_01_2 = {53 6d 73 5f 46 6f 72 77 61 72 64 65 72 2e 61 70 70 2e 6d 61 69 6e } //01 00  Sms_Forwarder.app.main
		$a_01_3 = {6e 65 74 2e 74 72 69 63 65 73 2e 77 65 62 76 69 65 77 } //00 00  net.trices.webview
	condition:
		any of ($a_*)
 
}