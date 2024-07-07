
rule TrojanSpy_AndroidOS_Fakeapp_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakeapp.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 68 6f 77 43 6f 6e 74 61 63 74 73 } //1 showContacts
		$a_01_1 = {63 68 65 63 6b 50 65 72 6d 69 73 73 69 6f 6e 4c 6f 61 64 } //1 checkPermissionLoad
		$a_01_2 = {6b 69 6c 6c 41 70 70 } //1 killApp
		$a_01_3 = {73 6d 73 6c 69 73 74 } //1 smslist
		$a_01_4 = {4c 63 6f 6d 2f 66 73 64 6b 66 64 6a 73 68 6b 6a 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //5 Lcom/fsdkfdjshkj/MainActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5) >=8
 
}