
rule TrojanSpy_AndroidOS_SmsThief_R_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 61 6e 61 61 70 6b } //1 com.sanaapk
		$a_00_1 = {63 6f 6d 2e 4d 61 72 73 4d 61 6e } //1 com.MarsMan
		$a_00_2 = {67 65 74 4c 61 73 74 53 6d 73 } //1 getLastSms
		$a_00_3 = {68 69 64 65 41 70 70 49 63 6f 6e } //1 hideAppIcon
		$a_00_4 = {74 65 73 74 2e 74 65 73 74 } //1 test.test
		$a_00_5 = {73 6d 63 6f 6e 74 61 63 74 73 } //1 smcontacts
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}