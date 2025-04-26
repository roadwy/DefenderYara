
rule Trojan_AndroidOS_FakeInstSms_C{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 72 75 6e 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //1 AutorunBroadcastReceiver
		$a_01_1 = {2f 63 6f 6e 6e 65 63 74 2e 70 68 70 00 } //1
		$a_01_2 = {73 74 61 74 20 6d 61 6e 6e 75 61 6c 79 00 } //1 瑳瑡洠湡畮污y
		$a_01_3 = {53 6d 73 52 65 63 69 76 65 72 2e 6a 61 76 61 00 } //1 浓剳捥癩牥樮癡a
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Trojan_AndroidOS_FakeInstSms_C_2{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.C,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {42 69 6e 61 72 79 53 4d 53 52 65 63 65 69 76 65 72 2e 6a 61 76 61 } //1 BinarySMSReceiver.java
		$a_00_1 = {4c 63 6f 6d 2f 73 6f 66 74 2f 61 6e 64 72 6f 69 64 2f 61 70 70 69 6e 73 74 61 6c 6c 65 72 2f 73 65 72 76 69 63 65 73 2f 53 4d 53 53 65 6e 64 65 72 53 65 72 76 69 63 65 } //1 Lcom/soft/android/appinstaller/services/SMSSenderService
		$a_00_2 = {53 6f 72 74 69 6e 67 20 53 4d 53 2e 2e 2e } //1 Sorting SMS...
		$a_00_3 = {64 63 53 6d 73 43 6f 75 6e 74 } //1 dcSmsCount
		$a_00_4 = {66 69 6c 6c 53 6d 73 49 6e 66 6f 28 29 } //1 fillSmsInfo()
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}