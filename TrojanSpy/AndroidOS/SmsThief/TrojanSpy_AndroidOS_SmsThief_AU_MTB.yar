
rule TrojanSpy_AndroidOS_SmsThief_AU_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AU!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 4d 65 73 73 61 67 65 73 } //1 uploadMessages
		$a_01_1 = {4d 65 73 73 61 67 65 52 65 63 65 69 76 65 72 4c 69 73 74 65 6e 65 72 } //1 MessageReceiverListener
		$a_01_2 = {48 74 74 70 4c 6f 67 67 69 6e 67 49 6e 74 65 72 63 65 70 74 6f 72 } //1 HttpLoggingInterceptor
		$a_01_3 = {63 6f 2f 74 65 63 68 69 76 65 2f 64 6d 61 72 74 2f 53 4d 53 52 65 63 65 69 76 65 72 } //1 co/techive/dmart/SMSReceiver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}