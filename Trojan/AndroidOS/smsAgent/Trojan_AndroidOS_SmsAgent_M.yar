
rule Trojan_AndroidOS_SmsAgent_M{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.M,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 48 4f 57 5f 53 54 41 52 54 5f 53 4d 53 5f 53 45 56 49 43 45 } //2 SHOW_START_SMS_SEVICE
		$a_01_1 = {53 45 4e 44 5f 48 45 4c 4c 4f 53 41 59 5f 43 41 54 43 48 } //2 SEND_HELLOSAY_CATCH
		$a_01_2 = {53 41 56 45 5f 50 45 52 5f 49 4e 49 54 5f 53 59 53 54 45 4d } //2 SAVE_PER_INIT_SYSTEM
		$a_01_3 = {73 68 6f 77 44 69 61 6c 6f 67 4e 6f 74 69 66 69 53 65 6e 64 53 4d 53 } //2 showDialogNotifiSendSMS
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}