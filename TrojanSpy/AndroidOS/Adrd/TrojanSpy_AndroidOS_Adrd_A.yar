
rule TrojanSpy_AndroidOS_Adrd_A{
	meta:
		description = "TrojanSpy:AndroidOS/Adrd.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {61 64 72 64 2e 78 69 61 78 69 61 62 2e 63 6f 6d 2f 70 69 63 2e 61 73 70 78 3f 69 6d 3d 90 09 07 00 68 74 74 70 3a 2f 2f } //2
		$a_01_1 = {4d 30 33 32 38 39 30 35 30 30 31 37 30 37 35 38 2e 6d 70 33 } //1 M032890500170758.mp3
		$a_01_2 = {67 6f 5f 67 31 5f 73 6d 73 } //1 go_g1_sms
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}