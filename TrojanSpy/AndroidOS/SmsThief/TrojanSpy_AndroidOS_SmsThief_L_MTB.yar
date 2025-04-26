
rule TrojanSpy_AndroidOS_SmsThief_L_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 72 65 61 6c 73 70 79 2f } //2 /realspy/
		$a_00_1 = {2f 72 65 61 6c 72 61 74 2f } //2 /realrat/
		$a_00_2 = {73 6d 73 74 6f 63 6f 6e 74 61 63 74 73 } //1 smstocontacts
		$a_00_3 = {68 69 64 65 61 70 6b } //1 hideapk
		$a_00_4 = {63 6f 6e 74 61 63 74 73 2e 74 78 74 } //1 contacts.txt
		$a_00_5 = {53 4d 53 49 6e 74 65 72 63 65 70 74 6f 72 } //1 SMSInterceptor
		$a_00_6 = {70 6f 73 74 5f 64 61 74 61 } //1 post_data
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule TrojanSpy_AndroidOS_SmsThief_L_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 4b 72 79 70 74 6f 73 6d 73 3b } //2 /Kryptosms;
		$a_00_1 = {2f 41 75 74 6f 53 65 72 76 69 63 65 3b } //1 /AutoService;
		$a_00_2 = {2f 4c 75 6b 61 73 } //1 /Lukas
		$a_00_3 = {66 69 6e 64 41 63 63 65 73 73 69 62 69 6c 69 74 79 4e 6f 64 65 49 6e 66 6f 73 42 79 56 69 65 77 49 64 } //1 findAccessibilityNodeInfosByViewId
		$a_00_4 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getDisplayMessageBody
		$a_00_5 = {70 65 72 66 6f 72 6d 41 63 74 69 6f 6e } //1 performAction
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}