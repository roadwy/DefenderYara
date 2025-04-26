
rule TrojanSpy_AndroidOS_FakeView_DS_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeView.DS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 62 69 6c 65 73 70 79 } //1 Mobilespy
		$a_00_1 = {4e 4f 20 53 4d 53 20 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 } //1 NO SMS $$$$$$$$$$$$$$$$$
		$a_00_2 = {43 68 65 63 6b 69 6e 67 20 66 6f 72 20 4f 75 74 67 6f 69 6e 67 20 53 4d 53 } //1 Checking for Outgoing SMS
		$a_00_3 = {73 70 79 5f 64 62 } //1 spy_db
		$a_00_4 = {63 65 6c 6c 70 68 6f 6e 65 72 65 63 6f 6e 2e 63 6f 6d } //1 cellphonerecon.com
		$a_00_5 = {43 6f 6e 74 61 63 74 55 70 6c 6f 61 64 65 72 } //1 ContactUploader
		$a_00_6 = {43 61 6c 6c 53 70 79 } //1 CallSpy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}