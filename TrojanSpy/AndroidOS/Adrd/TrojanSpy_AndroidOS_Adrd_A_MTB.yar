
rule TrojanSpy_AndroidOS_Adrd_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Adrd.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 61 64 6d 67 72 2e 72 65 65 66 63 75 62 65 2e 62 69 7a 2f 65 6d 61 69 6c 2e 70 68 70 } //1 androadmgr.reefcube.biz/email.php
		$a_01_1 = {73 65 6e 64 4d 61 69 6c 73 } //1 sendMails
		$a_01_2 = {63 6f 6d 2e 6e 6f 69 73 79 73 6f 75 6e 64 73 } //1 com.noisysounds
		$a_01_3 = {61 72 72 43 6f 6e 74 61 63 74 73 45 6d 61 69 6c 73 } //1 arrContactsEmails
		$a_01_4 = {2f 61 64 72 64 2e 78 69 61 78 69 61 62 2e 63 6f 6d } //1 /adrd.xiaxiab.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}