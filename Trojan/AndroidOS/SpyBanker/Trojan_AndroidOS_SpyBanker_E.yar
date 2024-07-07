
rule Trojan_AndroidOS_SpyBanker_E{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.E,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 52 65 61 64 41 6e 64 52 65 63 65 69 76 65 41 6e 64 53 65 6e 64 53 6d 73 } //1 checkReadAndReceiveAndSendSms
		$a_01_1 = {63 68 65 63 6b 43 61 70 74 75 72 65 4d 69 63 } //1 checkCaptureMic
		$a_01_2 = {69 6e 73 70 65 63 74 6f 72 50 72 65 66 73 } //1 inspectorPrefs
		$a_01_3 = {63 68 65 63 6b 43 61 70 74 75 72 65 43 61 6d } //1 checkCaptureCam
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}