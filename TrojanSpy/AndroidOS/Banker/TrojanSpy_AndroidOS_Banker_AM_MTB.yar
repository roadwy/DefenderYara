
rule TrojanSpy_AndroidOS_Banker_AM_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AM!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {74 65 78 74 53 50 41 4d } //1 textSPAM
		$a_00_1 = {73 70 61 6d 53 4d 53 } //1 spamSMS
		$a_00_2 = {6b 65 79 73 2e 6c 6f 67 } //1 keys.log
		$a_00_3 = {6b 69 6c 6c 42 6f 74 20 2d 3e 20 43 6f 6d 6d 61 6e 64 73 } //1 killBot -> Commands
		$a_00_4 = {69 6e 64 65 78 53 4d 53 53 50 41 4d } //1 indexSMSSPAM
		$a_00_5 = {53 54 41 52 54 20 52 45 43 4f 52 44 20 53 4f 55 4e 44 } //1 START RECORD SOUND
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}