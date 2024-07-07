
rule Trojan_AndroidOS_JSmsHider_B_MTB{
	meta:
		description = "Trojan:AndroidOS/JSmsHider.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 62 69 6c 65 2e 33 67 77 6c 64 68 2e 63 6f 6d } //1 mobile.3gwldh.com
		$a_01_1 = {48 61 6e 64 69 6e 67 43 61 6c 6c 4c 69 73 74 65 6e 65 72 } //1 HandingCallListener
		$a_01_2 = {41 43 54 49 4f 4e 5f 4c 49 53 54 45 4e 5f 53 4d 53 } //1 ACTION_LISTEN_SMS
		$a_01_3 = {53 4d 53 4f 62 73 65 72 76 65 72 } //1 SMSObserver
		$a_01_4 = {49 4e 54 45 4e 41 4c 5f 41 43 54 49 4f 4e 5f 50 68 6f 6e 65 43 61 6c 6c 52 65 63 6f 72 64 } //1 INTENAL_ACTION_PhoneCallRecord
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}