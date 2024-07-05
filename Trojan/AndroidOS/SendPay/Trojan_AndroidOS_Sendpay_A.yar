
rule Trojan_AndroidOS_Sendpay_A{
	meta:
		description = "Trojan:AndroidOS/Sendpay.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 73 74 69 6e 65 64 5f 78 68 61 6c 66 5f 66 72 65 65 } //01 00  destined_xhalf_free
		$a_01_1 = {43 6f 75 6c 64 20 6e 6f 74 20 73 65 6e 64 20 73 6d 73 20 74 6f 20 6e 75 6d 62 65 72 } //01 00  Could not send sms to number
		$a_01_2 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 61 70 70 2d 73 74 6f 72 65 } //00 00  application/x-app-store
	condition:
		any of ($a_*)
 
}