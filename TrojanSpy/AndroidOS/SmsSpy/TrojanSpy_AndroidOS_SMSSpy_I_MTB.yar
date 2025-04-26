
rule TrojanSpy_AndroidOS_SMSSpy_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 76 41 64 52 65 63 65 69 76 65 72 } //1 DevAdReceiver
		$a_01_1 = {73 65 6e 64 48 74 74 70 41 64 64 44 65 76 } //1 sendHttpAddDev
		$a_01_2 = {6d 44 65 6c 65 74 65 43 61 6c 6c 4c 6f 67 48 61 6e 64 6c 65 72 } //1 mDeleteCallLogHandler
		$a_01_3 = {73 65 6e 64 53 4d 53 32 4c 6f 6e 67 } //1 sendSMS2Long
		$a_01_4 = {2f 73 6f 61 70 69 2f 67 65 74 6d 73 67 73 } //1 /soapi/getmsgs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}