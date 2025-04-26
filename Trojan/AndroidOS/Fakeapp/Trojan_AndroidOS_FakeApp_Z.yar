
rule Trojan_AndroidOS_FakeApp_Z{
	meta:
		description = "Trojan:AndroidOS/FakeApp.Z,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 53 6d 73 44 61 74 61 55 70 6c 6f 61 64 } //2 getSmsDataUpload
		$a_01_1 = {77 65 62 61 70 70 2f 73 61 76 65 53 6d 73 } //2 webapp/saveSms
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}