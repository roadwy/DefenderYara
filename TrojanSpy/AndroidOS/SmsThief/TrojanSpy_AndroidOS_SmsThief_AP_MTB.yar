
rule TrojanSpy_AndroidOS_SmsThief_AP_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AP!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 78 74 72 61 63 74 4d 65 73 73 61 67 65 73 } //1 extractMessages
		$a_01_1 = {44 61 74 61 52 65 71 75 65 73 74 28 73 65 6e 64 65 72 5f 6e 6f 3d } //1 DataRequest(sender_no=
		$a_01_2 = {73 61 76 65 5f 73 6d 73 2e 70 68 70 } //1 save_sms.php
		$a_01_3 = {39 31 31 38 39 31 39 36 37 38 } //1 9118919678
		$a_01_4 = {4c 62 72 2f 63 6f 6d 2f 68 65 6c 70 64 65 76 2f 6b 79 63 66 6f 72 6d } //1 Lbr/com/helpdev/kycform
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}