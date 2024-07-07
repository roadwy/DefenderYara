
rule TrojanSpy_AndroidOS_SmForw_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 73 65 68 6f 73 74 } //1 usehost
		$a_01_1 = {2f 6c 6f 67 69 6e 2e 70 68 70 } //1 /login.php
		$a_01_2 = {63 6f 6d 2f 43 6f 70 6f 6e 2f 53 4d 53 } //1 com/Copon/SMS
		$a_01_3 = {63 6c 53 65 72 76 69 63 65 } //1 clService
		$a_01_4 = {73 6d 73 2e 70 68 70 } //1 sms.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}