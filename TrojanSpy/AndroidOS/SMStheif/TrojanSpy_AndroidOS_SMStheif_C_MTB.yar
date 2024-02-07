
rule TrojanSpy_AndroidOS_SMStheif_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMStheif.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,3d 00 3d 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {67 72 61 62 62 65 64 5f 6c 69 73 74 } //0a 00  grabbed_list
		$a_01_1 = {47 52 41 42 42 45 44 5f 53 4d 53 } //0a 00  GRABBED_SMS
		$a_00_2 = {73 61 76 65 4d 65 73 73 61 67 65 } //0a 00  saveMessage
		$a_00_3 = {73 65 6e 64 53 6d 73 41 6e 64 53 61 76 65 4e 75 6d 62 65 72 } //0a 00  sendSmsAndSaveNumber
		$a_01_4 = {74 65 6c 5f 6e 75 6d } //0a 00  tel_num
		$a_00_5 = {67 65 74 43 75 72 72 65 6e 74 54 65 6c 65 70 68 6f 6e 65 50 61 72 61 6d 73 } //01 00  getCurrentTelephoneParams
		$a_00_6 = {70 61 6e 65 6c 2e 72 65 } //01 00  panel.re
		$a_00_7 = {70 61 6e 65 6c 76 72 2e 69 6e } //01 00  panelvr.in
		$a_00_8 = {70 61 6e 65 6c 76 72 2e 6d 6f 62 69 } //01 00  panelvr.mobi
		$a_00_9 = {76 72 70 61 6e 65 6c 2e 62 69 7a } //00 00  vrpanel.biz
		$a_00_10 = {5d 04 00 00 e7 f9 04 80 5c 25 00 00 e8 f9 04 80 00 00 01 00 27 00 0f 00 c8 a1 46 69 6e 53 70 79 2e 56 42 21 4d 54 42 00 00 } //01 40 
	condition:
		any of ($a_*)
 
}