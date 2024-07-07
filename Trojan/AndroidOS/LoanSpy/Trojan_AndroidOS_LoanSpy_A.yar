
rule Trojan_AndroidOS_LoanSpy_A{
	meta:
		description = "Trojan:AndroidOS/LoanSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 69 6e 67 20 73 79 6e 63 53 4d 53 } //2 calling syncSMS
		$a_01_1 = {4d 61 6e 61 67 65 54 65 78 74 4d 65 73 73 61 67 65 73 53 65 72 76 69 63 65 } //2 ManageTextMessagesService
		$a_01_2 = {44 65 76 69 63 65 53 74 61 74 75 73 53 79 6e 63 55 74 69 6c 73 } //2 DeviceStatusSyncUtils
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}