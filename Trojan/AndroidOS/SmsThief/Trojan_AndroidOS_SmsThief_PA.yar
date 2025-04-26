
rule Trojan_AndroidOS_SmsThief_PA{
	meta:
		description = "Trojan:AndroidOS/SmsThief.PA,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 6d 73 2f 68 61 63 6b 2f 44 65 62 75 67 41 63 74 69 76 69 74 79 } //2 sms/hack/DebugActivity
		$a_01_1 = {5f 69 61 6d 41 6e 74 69 6b } //2 _iamAntik
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}