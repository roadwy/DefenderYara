
rule TrojanSpy_AndroidOS_Dingwe_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Dingwe.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 69 6e 62 6f 78 73 6d 73 } //1 getinboxsms
		$a_01_1 = {2f 4b 65 79 4c 6f 67 2e 74 78 74 } //1 /KeyLog.txt
		$a_01_2 = {63 6f 6d 2e 63 6f 6e 6e 65 63 74 } //1 com.connect
		$a_01_3 = {43 6f 6e 74 61 63 74 73 2e 74 78 74 } //1 Contacts.txt
		$a_01_4 = {2f 6e 65 77 2d 75 70 6c 6f 61 64 2e 70 68 70 } //1 /new-upload.php
		$a_01_5 = {53 6d 73 5f 53 65 6e 74 2e 74 78 74 } //1 Sms_Sent.txt
		$a_01_6 = {64 65 6c 65 74 65 63 61 6c 6c 6c 6f 67 6e 75 6d 62 65 72 } //1 deletecalllognumber
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}