
rule TrojanSpy_AndroidOS_SmsThief_Y_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {4c 63 6f 6d 2f 68 65 6c 70 64 65 76 2f [0-10] 73 75 70 70 6f 72 74 2f 75 74 69 6c 73 2f 4d 79 53 65 72 76 69 63 65 3b } //1
		$a_00_1 = {73 61 76 65 5f 73 6d 73 2e 70 68 70 } //1 save_sms.php
		$a_00_2 = {09 73 6d 73 5f 72 65 63 76 65 00 } //1
		$a_00_3 = {73 65 6e 64 6f 72 5f 6e 6f } //1 sendor_no
		$a_00_4 = {2f 63 6f 6e 74 72 6f 6c 6c 65 72 2f 61 70 69 2f 63 6f 6d 6d 6f 6e 2f } //1 /controller/api/common/
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}