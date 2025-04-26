
rule TrojanSpy_AndroidOS_Piom_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Piom.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {69 72 2e 61 2e 74 65 73 74 66 69 72 65 62 61 73 65 } //1 ir.a.testfirebase
		$a_00_1 = {73 61 6a 6a 61 64 34 35 38 30 } //1 sajjad4580
		$a_00_2 = {72 65 67 69 73 74 65 72 3a 20 63 6f 6d 6d 65 64 } //1 register: commed
		$a_01_3 = {73 65 6e 64 6d 75 6c 74 69 73 6d 73 } //1 sendmultisms
		$a_01_4 = {61 70 70 53 6d 73 4c 6f 67 67 65 72 } //1 appSmsLogger
		$a_00_5 = {2f 55 70 6c 6f 61 64 53 6d 73 2e 70 68 70 } //1 /UploadSms.php
		$a_00_6 = {2f 47 65 74 4c 69 6e 6b 2e 70 68 70 } //1 /GetLink.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}