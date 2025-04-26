
rule TrojanSpy_AndroidOS_MisoSpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/MisoSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 53 69 6e 52 65 63 76 3b } //1 /SinRecv;
		$a_01_1 = {2f 4c 53 65 63 53 63 72 65 65 6e 3b } //1 /LSecScreen;
		$a_01_2 = {52 65 71 75 65 73 74 53 74 72 75 63 74 5f 52 65 63 50 68 6f 6e 65 49 6e 66 6f } //1 RequestStruct_RecPhoneInfo
		$a_01_3 = {61 72 72 61 79 4f 66 53 6d 73 4d 65 73 73 61 67 65 } //1 arrayOfSmsMessage
		$a_01_4 = {73 74 61 72 74 41 64 64 44 65 76 69 63 65 41 64 6d 69 6e 41 74 79 } //1 startAddDeviceAdminAty
		$a_01_5 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 69 6e 62 6f 78 } //1 content://sms/inbox
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}