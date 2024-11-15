
rule TrojanSpy_AndroidOS_SmsSpy_P_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 72 69 61 73 68 69 72 61 7a 69 2f 69 6e 73 74 61 62 72 6f 77 73 65 72 } //1 com/ariashirazi/instabrowser
		$a_01_1 = {3f 64 65 76 69 63 65 2d 69 6e 66 6f 3d } //1 ?device-info=
		$a_01_2 = {4e 75 72 41 6c 61 6d 34 } //1 NurAlam4
		$a_01_3 = {75 72 6c 20 6f 70 65 6e 65 64 20 3a } //1 url opened :
		$a_01_4 = {73 65 6e 64 53 6d 73 54 6f 53 65 72 76 65 72 } //1 sendSmsToServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}