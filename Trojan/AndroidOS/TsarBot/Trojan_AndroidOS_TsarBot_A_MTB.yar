
rule Trojan_AndroidOS_TsarBot_A_MTB{
	meta:
		description = "Trojan:AndroidOS/TsarBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 67 6f 6f 67 6c 65 70 6c 61 79 73 65 72 76 69 63 65 } //1 com/example/googleplayservice
		$a_01_1 = {74 74 70 73 3a 2f 2f 78 64 6a 68 67 66 67 6a 68 2e 72 75 6e 2f 69 6e 6a 65 63 74 73 2f } //1 ttps://xdjhgfgjh.run/injects/
		$a_01_2 = {53 63 72 65 65 6e 43 61 70 74 75 72 65 53 65 72 76 69 63 65 } //1 ScreenCaptureService
		$a_01_3 = {70 61 73 73 77 6f 72 64 5f 69 6e 6a 65 63 74 } //1 password_inject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}