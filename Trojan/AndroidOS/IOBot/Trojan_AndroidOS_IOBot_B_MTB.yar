
rule Trojan_AndroidOS_IOBot_B_MTB{
	meta:
		description = "Trojan:AndroidOS/IOBot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6b 72 2e 6d 74 } //2 com.kr.mt
		$a_01_1 = {49 4f 42 6f 74 2e 67 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 IOBot.getPhoneNumber
		$a_01_2 = {49 4f 42 6f 74 2e 67 65 74 50 68 6f 6e 65 4d 6f 64 65 6c } //1 IOBot.getPhoneModel
		$a_01_3 = {49 4f 42 6f 74 2e 67 65 74 53 63 72 65 65 6e 53 74 61 74 75 73 } //1 IOBot.getScreenStatus
		$a_01_4 = {73 65 72 76 69 63 65 73 2e 41 70 70 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //1 services.AppAccessibilityService
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}