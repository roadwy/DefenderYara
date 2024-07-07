
rule Trojan_AndroidOS_PJapps_B_MTB{
	meta:
		description = "Trojan:AndroidOS/PJapps.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 72 64 64 65 74 61 69 6c 73 65 6e 64 6d 73 67 } //1 frddetailsendmsg
		$a_01_1 = {4d 73 67 53 65 6e 64 41 63 74 69 76 69 74 79 } //1 MsgSendActivity
		$a_01_2 = {4c 69 6e 66 6f 53 65 74 74 69 6e 67 50 65 72 73 6f 6e 61 6c 69 6e 66 6f } //1 LinfoSettingPersonalinfo
		$a_01_3 = {67 72 6f 75 70 6d 73 67 5f 6d 73 67 73 65 6e 64 } //1 groupmsg_msgsend
		$a_01_4 = {63 6f 6d 2e 74 65 73 74 2e 73 6d 73 2e 73 65 6e 64 } //1 com.test.sms.send
		$a_01_5 = {2f 73 64 63 61 72 64 2f 61 6e 64 72 6f 69 64 68 2e 6c 6f 67 } //1 /sdcard/androidh.log
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}