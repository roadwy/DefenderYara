
rule TrojanSpy_AndroidOS_HippoSms_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/HippoSms.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 65 73 73 61 67 65 5f 73 65 6e 64 73 6d 73 5f 73 75 63 63 65 73 73 } //1 message_sendsms_success
		$a_00_1 = {66 6f 72 63 65 55 70 67 72 61 64 65 } //1 forceUpgrade
		$a_00_2 = {72 65 63 6f 6d 6d 65 6e 64 5f 73 65 6c 66 5f 70 68 6f 6e 65 6e 75 6d 62 65 72 } //1 recommend_self_phonenumber
		$a_00_3 = {62 61 6e 6b 2e 68 74 6d 6c } //1 bank.html
		$a_00_4 = {72 73 5f 75 70 64 61 74 65 2e 61 70 6b } //1 rs_update.apk
		$a_00_5 = {64 6f 77 6e 6c 6f 61 64 69 6e 67 20 6c 61 74 65 73 74 20 61 70 6b } //1 downloading latest apk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}