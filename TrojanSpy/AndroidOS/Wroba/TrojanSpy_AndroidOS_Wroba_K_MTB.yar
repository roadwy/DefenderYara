
rule TrojanSpy_AndroidOS_Wroba_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 6d 73 20 4c 6f 63 6b } //1 sms Lock
		$a_01_1 = {6e 6f 74 69 66 79 20 75 70 6c 6f 61 64 20 72 65 73 75 6c 74 } //1 notify upload result
		$a_01_2 = {64 62 34 53 4d 53 } //1 db4SMS
		$a_01_3 = {77 65 62 63 61 73 68 2e 77 6f 6f 72 69 62 61 6e 6b } //1 webcash.wooribank
		$a_01_4 = {61 64 64 2e 70 68 70 20 72 65 73 75 6c 74 } //1 add.php result
		$a_01_5 = {75 70 6c 6f 61 64 5f 73 6d 73 20 73 74 61 72 74 } //1 upload_sms start
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}