
rule Trojan_AndroidOS_SmsSpy_L{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.L,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 65 6b 68 6d 65 73 73 61 67 65 } //2 dekhmessage
		$a_01_1 = {65 78 61 6d 70 6c 65 6e 6f 20 6e 75 6e 62 65 72 } //2 exampleno nunber
		$a_01_2 = {63 6f 6d 2e 6d 79 2e 75 70 64 61 74 65 } //2 com.my.update
		$a_01_3 = {6d 79 63 6f 6d 70 6c 61 69 6e 71 75 65 72 79 2e 69 6e 2f 61 70 69 } //2 mycomplainquery.in/api
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}