
rule TrojanSpy_AndroidOS_Bian_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Bian.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 6f 72 72 79 21 6e 65 65 64 38 6d 6f 6e 65 79 5b 66 6f 72 60 66 6f 6f 64 } //1 sorry!need8money[for`food
		$a_00_1 = {41 6e 64 72 6f 69 64 42 6f 74 } //1 AndroidBot
		$a_00_2 = {6f 6e 49 6e 6a 65 63 74 4e 6f 74 69 66 69 63 61 74 69 6f 6e 52 65 63 65 69 76 65 64 } //1 onInjectNotificationReceived
		$a_00_3 = {53 63 72 65 65 6e 63 61 73 74 } //1 Screencast
		$a_00_4 = {64 65 6c 65 74 65 53 4d 53 } //1 deleteSMS
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}