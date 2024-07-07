
rule Trojan_AndroidOS_FakeApp_H{
	meta:
		description = "Trojan:AndroidOS/FakeApp.H,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 65 62 61 6e 64 72 6f 69 64 5f 69 73 66 69 72 73 74 5f 65 6e 63 6f 6d 65 } //2 webandroid_isfirst_encome
		$a_00_1 = {57 52 49 54 45 5f 41 4e 44 5f 52 45 41 44 5f 45 58 54 45 52 4e 41 4c 5f 43 4f 44 45 } //2 WRITE_AND_READ_EXTERNAL_CODE
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}