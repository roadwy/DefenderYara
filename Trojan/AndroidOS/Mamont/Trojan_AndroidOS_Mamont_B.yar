
rule Trojan_AndroidOS_Mamont_B{
	meta:
		description = "Trojan:AndroidOS/Mamont.B,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 73 54 65 6c 65 67 72 61 6d 53 65 6e 64 65 64 5f 31 } //1 isTelegramSended_1
		$a_01_1 = {53 6d 73 47 72 61 62 62 65 72 3a 20 4e 6f 20 6d 65 73 73 61 67 65 73 20 66 6f 75 6e 64 } //1 SmsGrabber: No messages found
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}