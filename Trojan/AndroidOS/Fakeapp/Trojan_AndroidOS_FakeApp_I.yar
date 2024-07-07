
rule Trojan_AndroidOS_FakeApp_I{
	meta:
		description = "Trojan:AndroidOS/FakeApp.I,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 44 75 70 68 6f 6e 67 } //2 sendDuphong
		$a_01_1 = {2f 73 61 76 65 2d 70 68 6f 6e 65 2d 6c 6f 67 73 } //2 /save-phone-logs
		$a_01_2 = {75 72 6c 41 6f 63 } //2 urlAoc
		$a_01_3 = {2f 61 70 69 2f 6b 65 79 77 6f 72 64 73 2d 69 6e 66 6f } //2 /api/keywords-info
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}