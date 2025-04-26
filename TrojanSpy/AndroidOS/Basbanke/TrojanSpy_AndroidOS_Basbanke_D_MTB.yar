
rule TrojanSpy_AndroidOS_Basbanke_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Basbanke.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6e 6a 65 63 74 5f 61 63 74 69 76 69 74 79 } //1 inject_activity
		$a_01_1 = {67 65 74 64 65 66 61 75 6c 74 73 6d 73 5f 61 63 74 69 76 69 74 79 } //1 getdefaultsms_activity
		$a_01_2 = {50 68 6f 6e 65 53 6d 73 } //1 PhoneSms
		$a_01_3 = {67 65 74 70 61 73 73 61 63 74 69 76 69 74 79 } //1 getpassactivity
		$a_01_4 = {73 6d 73 5f 64 65 6c 69 76 65 72 } //1 sms_deliver
		$a_01_5 = {66 61 6b 65 70 69 6e 5f 61 63 74 69 76 69 74 79 } //1 fakepin_activity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}