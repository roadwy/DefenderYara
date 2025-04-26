
rule TrojanSpy_AndroidOS_Banker_AF_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 68 77 2f 6a 78 65 6b 77 78 6a 73 68 79 43 75 2f 69 75 73 6b 68 75 69 43 69 } //1 ehw/jxekwxjshyCu/iuskhuiCi
		$a_01_1 = {6d 6d 73 63 2e 6d 6f 6e 74 65 72 6e 65 74 2e 63 6f 6d } //1 mmsc.monternet.com
		$a_01_2 = {74 72 2f 73 65 72 76 6c 65 74 73 2f 6d 6d 73 } //1 tr/servlets/mms
		$a_01_3 = {6c 6f 63 6b 4e 6f 77 } //1 lockNow
		$a_01_4 = {72 65 73 65 74 50 61 73 73 77 6f 72 64 } //1 resetPassword
		$a_01_5 = {65 68 77 2f 6a 78 65 6b 77 78 6a 73 68 79 43 75 2f 69 75 73 6b 68 75 69 43 69 2f 64 65 6a 79 76 79 73 71 6a 79 65 64 69 2f 70 71 68 6e 48 75 71 74 48 75 73 75 79 6c 75 68 } //1 ehw/jxekwxjshyCu/iuskhuiCi/dejyvysqjyedi/pqhnHuqtHusuyluh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}