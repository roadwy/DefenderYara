
rule TrojanSpy_AndroidOS_SmsThief_AX_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AX!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6e 73 65 72 74 5f 6d 65 73 73 61 67 65 73 2e 70 68 70 } //1 insert_messages.php
		$a_01_1 = {69 73 5f 66 77 64 5f 73 6d 73 } //1 is_fwd_sms
		$a_01_2 = {63 6f 6d 2f 63 61 6c 6c 67 69 72 6c 73 73 65 72 76 69 63 65 73 } //1 com/callgirlsservices
		$a_01_3 = {63 61 6c 6c 5f 63 6c 69 63 6b } //1 call_click
		$a_01_4 = {62 79 70 61 73 73 5f 32 30 30 } //1 bypass_200
		$a_01_5 = {73 65 6e 64 5f 73 6d 73 5f 74 6f } //1 send_sms_to
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}