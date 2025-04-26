
rule TrojanSpy_AndroidOS_SmsThief_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 65 61 6c 72 61 74 2f } //2 realrat/
		$a_00_1 = {5f 66 75 63 6b } //1 _fuck
		$a_00_2 = {5f 75 70 6c 6f 61 64 73 75 63 65 73 73 } //1 _uploadsucess
		$a_00_3 = {50 68 6f 6e 65 53 6d 73 } //1 PhoneSms
		$a_00_4 = {53 4d 53 49 6e 74 65 72 63 65 70 74 6f 72 } //1 SMSInterceptor
		$a_00_5 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getDisplayMessageBody
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule TrojanSpy_AndroidOS_SmsThief_K_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 73 69 70 68 6f 6e 33 2f 66 69 72 65 62 61 73 65 6d 65 73 73 61 67 69 6e 67 3b } //2 Lcom/psiphon3/firebasemessaging;
		$a_00_1 = {4c 63 6f 6d 2f 73 70 69 6e 74 65 72 2f 75 70 6c 6f 61 64 66 69 6c 65 70 68 70 2f } //2 Lcom/spinter/uploadfilephp/
		$a_00_2 = {2f 70 61 6e 65 6c 2e 70 68 70 3f 75 70 6c 6f 61 64 73 6d 73 3d } //1 /panel.php?uploadsms=
		$a_00_3 = {2f 70 68 6f 6e 65 2f 53 6d 73 57 72 61 70 70 65 72 } //1 /phone/SmsWrapper
		$a_00_4 = {2f 53 6d 73 2e 74 78 74 } //1 /Sms.txt
		$a_00_5 = {68 69 64 65 41 70 70 49 63 6f 6e } //1 hideAppIcon
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}