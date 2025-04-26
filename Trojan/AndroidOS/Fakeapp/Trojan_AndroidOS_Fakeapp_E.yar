
rule Trojan_AndroidOS_Fakeapp_E{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.E,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 37 2e 31 30 37 2e 38 30 2e 32 34 33 3a 31 36 37 37 39 2f 61 70 69 2f 75 70 6c 6f 61 64 49 6d 67 73 } //1 47.107.80.243:16779/api/uploadImgs
		$a_01_1 = {34 37 2e 31 30 37 2e 38 30 2e 32 34 33 3a 31 36 37 37 39 2f 61 70 69 2f 73 75 62 53 6d 73 4c 69 73 74 } //1 47.107.80.243:16779/api/subSmsList
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}