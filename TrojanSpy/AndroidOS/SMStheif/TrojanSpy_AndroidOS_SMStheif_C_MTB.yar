
rule TrojanSpy_AndroidOS_SMStheif_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMStheif.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,3d 00 3d 00 0a 00 00 "
		
	strings :
		$a_01_0 = {67 72 61 62 62 65 64 5f 6c 69 73 74 } //10 grabbed_list
		$a_01_1 = {47 52 41 42 42 45 44 5f 53 4d 53 } //10 GRABBED_SMS
		$a_00_2 = {73 61 76 65 4d 65 73 73 61 67 65 } //10 saveMessage
		$a_00_3 = {73 65 6e 64 53 6d 73 41 6e 64 53 61 76 65 4e 75 6d 62 65 72 } //10 sendSmsAndSaveNumber
		$a_01_4 = {74 65 6c 5f 6e 75 6d } //10 tel_num
		$a_00_5 = {67 65 74 43 75 72 72 65 6e 74 54 65 6c 65 70 68 6f 6e 65 50 61 72 61 6d 73 } //10 getCurrentTelephoneParams
		$a_00_6 = {70 61 6e 65 6c 2e 72 65 } //1 panel.re
		$a_00_7 = {70 61 6e 65 6c 76 72 2e 69 6e } //1 panelvr.in
		$a_00_8 = {70 61 6e 65 6c 76 72 2e 6d 6f 62 69 } //1 panelvr.mobi
		$a_00_9 = {76 72 70 61 6e 65 6c 2e 62 69 7a } //1 vrpanel.biz
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=61
 
}