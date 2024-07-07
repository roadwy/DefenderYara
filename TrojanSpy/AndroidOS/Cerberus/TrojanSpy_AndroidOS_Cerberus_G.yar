
rule TrojanSpy_AndroidOS_Cerberus_G{
	meta:
		description = "TrojanSpy:AndroidOS/Cerberus.G,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 63 74 69 6f 6e 3d 73 65 6e 64 4c 69 73 74 50 68 6f 6e 65 4e 75 6d 62 65 72 73 26 64 61 74 61 3d } //2 action=sendListPhoneNumbers&data=
		$a_00_1 = {73 65 6e 64 53 6d 73 4c 6f 67 73 26 64 61 74 61 3d } //2 sendSmsLogs&data=
		$a_00_2 = {53 65 6e 64 20 44 61 74 61 20 49 6e 6a 65 63 74 69 6f 6e 20 74 6f 20 53 65 72 76 65 72 3a } //2 Send Data Injection to Server:
		$a_00_3 = {6c 6f 67 73 43 6f 6e 74 61 63 74 73 } //2 logsContacts
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}