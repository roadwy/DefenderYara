
rule TrojanSpy_AndroidOS_SharkBot_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SharkBot.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 67 73 53 6e 69 66 66 65 72 } //1 logsSniffer
		$a_01_1 = {6c 6f 67 73 47 72 61 62 62 65 72 } //1 logsGrabber
		$a_01_2 = {65 6e 61 62 6c 65 4b 65 79 4c 6f 67 67 65 72 } //1 enableKeyLogger
		$a_01_3 = {63 6f 6e 66 69 67 53 61 76 65 53 4d 53 } //1 configSaveSMS
		$a_03_4 = {23 01 e5 1c d8 00 00 ff 3a 00 1b 00 6e 20 ?? ?? 04 00 0a 02 d8 03 00 ff df 02 ?? ?? 8e 22 50 02 01 00 3a 03 0e 00 d8 00 03 ff 6e 20 ?? ?? 34 00 0a 02 df 02 ?? ?? 8e 22 50 02 01 03 28 e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}