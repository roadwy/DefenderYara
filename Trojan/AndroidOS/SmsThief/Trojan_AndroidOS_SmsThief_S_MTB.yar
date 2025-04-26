
rule Trojan_AndroidOS_SmsThief_S_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {62 72 2e 63 6f 6d 2e 68 65 6c 70 64 65 76 2e 70 6e 70 } //1 br.com.helpdev.pnp
		$a_00_1 = {44 61 74 61 52 65 71 75 65 73 74 28 73 65 6e 64 65 72 5f 6e 6f 3d } //1 DataRequest(sender_no=
		$a_00_2 = {73 6d 73 5f 72 65 63 76 65 } //1 sms_recve
		$a_00_3 = {67 65 74 6d 6f 62 69 6c 6e 6f } //1 getmobilno
		$a_00_4 = {73 6d 73 2f 63 6f 6e 74 72 6f 6c 6c 65 72 } //1 sms/controller
		$a_00_5 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getDisplayMessageBody
		$a_00_6 = {73 61 76 65 5f 73 6d 73 2e 70 68 70 } //1 save_sms.php
		$a_00_7 = {61 64 6d 69 6e 5f 72 65 63 65 69 76 65 72 5f 73 74 61 74 75 73 5f 64 69 73 61 62 6c 65 64 } //1 admin_receiver_status_disabled
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}