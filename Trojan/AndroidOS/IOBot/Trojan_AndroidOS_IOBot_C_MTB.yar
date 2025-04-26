
rule Trojan_AndroidOS_IOBot_C_MTB{
	meta:
		description = "Trojan:AndroidOS/IOBot.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 4f 42 6f 74 2e 67 65 74 42 61 74 74 65 72 79 4c 65 76 65 6c } //1 IOBot.getBatteryLevel
		$a_01_1 = {49 4f 42 6f 74 2e 67 65 74 50 68 6f 6e 65 4d 6f 64 65 6c } //1 IOBot.getPhoneModel
		$a_01_2 = {49 4f 42 6f 74 2e 67 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 IOBot.getPhoneNumber
		$a_01_3 = {49 4f 42 6f 74 2e 67 65 74 53 63 72 65 65 6e 53 74 61 74 75 73 } //1 IOBot.getScreenStatus
		$a_01_4 = {68 69 64 64 65 6e 5f 76 6e 63 } //1 hidden_vnc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}