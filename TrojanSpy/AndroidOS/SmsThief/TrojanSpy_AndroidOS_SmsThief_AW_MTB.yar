
rule TrojanSpy_AndroidOS_SmsThief_AW_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AW!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 6d 61 69 6e 2e 70 68 70 3f 67 65 74 3d 73 6d 73 } //1 /main.php?get=sms
		$a_01_1 = {6f 6e 63 65 73 6d 73 2e 74 78 74 } //1 oncesms.txt
		$a_01_2 = {53 6d 73 49 6e 74 65 72 63 65 70 74 6f 72 } //1 SmsInterceptor
		$a_01_3 = {63 6f 6d 2e 73 61 64 65 72 61 74 2e 73 69 6e 61 } //1 com.saderat.sina
		$a_01_4 = {2f 73 61 64 65 72 61 74 2e 70 68 70 } //1 /saderat.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}