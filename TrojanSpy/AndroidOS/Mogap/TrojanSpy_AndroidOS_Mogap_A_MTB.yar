
rule TrojanSpy_AndroidOS_Mogap_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mogap.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 5f 4f 46 46 5f 4d 53 47 } //1 SMS_OFF_MSG
		$a_01_1 = {53 4d 53 53 65 6e 64 4a 6f 62 } //1 SMSSendJob
		$a_01_2 = {4a 48 49 4e 4d 73 67 52 65 63 65 69 76 65 72 } //1 JHINMsgReceiver
		$a_01_3 = {63 6f 6d 2f 73 65 72 76 69 63 65 6a 67 2f 73 65 63 } //1 com/servicejg/sec
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}