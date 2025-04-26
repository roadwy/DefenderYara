
rule TrojanSpy_AndroidOS_SmsSpy_N_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 44 72 61 67 6f 6e 2f 63 6f 6e 76 65 72 74 } //1 com/Dragon/convert
		$a_00_1 = {73 6d 73 66 61 6f 72 79 } //1 smsfaory
		$a_00_2 = {41 72 61 62 57 61 72 65 53 4d 53 } //1 ArabWareSMS
		$a_00_3 = {73 6d 73 66 61 77 72 79 } //1 smsfawry
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}