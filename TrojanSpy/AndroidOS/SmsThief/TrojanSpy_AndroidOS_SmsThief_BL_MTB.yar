
rule TrojanSpy_AndroidOS_SmsThief_BL_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BL!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 65 6e 74 65 72 2f 61 75 74 6f 63 61 6d 65 72 61 } //1 com/senter/autocamera
		$a_01_1 = {44 72 61 77 43 61 70 74 75 72 65 52 65 63 74 } //1 DrawCaptureRect
		$a_01_2 = {4d 50 55 45 6e 74 69 74 79 } //1 MPUEntity
		$a_01_3 = {4b 45 59 5f 44 42 4d 5f 4c 45 56 45 4c } //1 KEY_DBM_LEVEL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}