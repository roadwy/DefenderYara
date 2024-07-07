
rule TrojanSpy_AndroidOS_Banker_AH_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 77 61 72 64 43 6f 6e 74 65 6e 74 } //1 forwardContent
		$a_01_1 = {2f 73 61 76 65 5f 73 6d 73 2e 70 68 70 } //1 /save_sms.php
		$a_01_2 = {6d 79 73 6d 73 6d 61 6e 61 67 65 72 } //1 mysmsmanager
		$a_01_3 = {66 6f 72 77 61 72 64 4e 75 6d 62 65 72 } //1 forwardNumber
		$a_01_4 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 6f 74 70 2e 70 68 70 } //1 000webhostapp.com/otp.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}