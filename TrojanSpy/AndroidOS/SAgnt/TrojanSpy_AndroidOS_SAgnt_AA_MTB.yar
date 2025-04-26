
rule TrojanSpy_AndroidOS_SAgnt_AA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 78 74 72 61 5f 73 6d 73 5f 6e 6f } //1 extra_sms_no
		$a_01_1 = {74 74 70 73 3a 2f 2f 77 77 77 2e 73 6e 65 74 61 70 69 73 2e 63 6f 6d 2f 61 70 69 2f } //1 ttps://www.snetapis.com/api/
		$a_01_2 = {73 6d 73 2d 74 65 73 74 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 } //1 sms-test/install.php
		$a_01_3 = {74 68 69 73 5f 73 6d 73 5f 72 65 63 65 69 76 65 72 5f 61 70 70 } //1 this_sms_receiver_app
		$a_01_4 = {75 70 6c 6f 61 64 55 73 65 72 } //1 uploadUser
		$a_01_5 = {69 73 44 6f 6e 65 50 65 72 6d 69 73 73 69 6f 6e } //1 isDonePermission
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}