
rule Trojan_AndroidOS_FakeApp_Y{
	meta:
		description = "Trojan:AndroidOS/FakeApp.Y,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 6e 63 50 65 72 6d 69 73 73 69 6f 6e } //2 sysncPermission
		$a_01_1 = {67 65 74 53 6d 73 44 61 74 61 55 70 6c 6f 61 64 } //2 getSmsDataUpload
		$a_01_2 = {77 65 62 61 70 70 2f 73 61 76 65 41 64 64 72 65 73 73 42 6f 6f 6b } //2 webapp/saveAddressBook
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}