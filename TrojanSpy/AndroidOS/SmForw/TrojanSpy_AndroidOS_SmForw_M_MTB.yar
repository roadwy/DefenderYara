
rule TrojanSpy_AndroidOS_SmForw_M_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6e 6a 65 63 74 41 70 70 53 6d 73 52 65 63 65 69 76 65 72 } //1 injectAppSmsReceiver
		$a_01_1 = {67 65 74 43 75 72 72 65 6e 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 getCurrentPhoneNumber
		$a_03_2 = {63 6f 6d 2f 6d 65 73 73 61 67 65 66 6f 72 77 61 72 64 90 01 02 2f 63 75 73 74 6f 6d 65 72 90 00 } //1
		$a_01_3 = {69 6e 6a 65 63 74 41 70 70 52 65 70 6f 73 69 74 6f 72 79 } //1 injectAppRepository
		$a_01_4 = {66 6f 72 77 61 72 64 4d 65 73 73 61 67 65 } //1 forwardMessage
		$a_01_5 = {41 70 70 53 6d 73 52 65 63 65 69 76 65 72 5f 47 65 6e 65 72 61 74 65 64 49 6e 6a 65 63 74 6f 72 } //1 AppSmsReceiver_GeneratedInjector
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}