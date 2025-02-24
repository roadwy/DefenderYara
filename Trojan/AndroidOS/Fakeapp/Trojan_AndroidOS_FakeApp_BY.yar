
rule Trojan_AndroidOS_FakeApp_BY{
	meta:
		description = "Trojan:AndroidOS/FakeApp.BY,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 30 34 2e 32 33 33 2e 31 36 37 2e 31 31 36 2f 70 72 6f 64 2d 61 70 69 2f } //2 104.233.167.116/prod-api/
		$a_01_1 = {67 65 74 53 6d 73 44 61 74 61 55 70 6c 6f 61 64 } //2 getSmsDataUpload
		$a_01_2 = {73 79 73 6e 63 50 65 72 6d 69 73 73 69 6f 6e } //2 sysncPermission
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}