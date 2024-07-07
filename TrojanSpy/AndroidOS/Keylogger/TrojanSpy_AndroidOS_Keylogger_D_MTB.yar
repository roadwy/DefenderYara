
rule TrojanSpy_AndroidOS_Keylogger_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Keylogger.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {4a 6f 4b 65 52 5f 53 65 52 76 45 72 } //1 JoKeR_SeRvEr
		$a_01_1 = {2f 74 65 73 74 2f 6a 6f 6b 65 72 32 } //1 /test/joker2
		$a_01_2 = {70 68 6f 6e 65 6d 6f 6e 69 74 6f 72 } //1 phonemonitor
		$a_01_3 = {43 4d 5f 53 45 4e 44 53 4d 53 } //1 CM_SENDSMS
		$a_01_4 = {64 65 6c 65 74 65 2d 6a 6f 6b 65 72 } //1 delete-joker
		$a_01_5 = {48 61 6e 64 6c 65 43 61 6c 6c 69 6e 67 } //1 HandleCalling
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}