
rule TrojanSpy_AndroidOS_SMSSpy_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 51 6e 10 90 01 02 06 00 0a 02 12 00 34 10 08 00 22 00 90 01 02 70 20 90 01 02 50 00 11 00 48 03 05 00 94 04 00 02 6e 20 90 01 02 46 00 0a 04 b7 43 8d 33 4f 03 05 00 d8 00 00 01 28 ea 90 00 } //2
		$a_00_1 = {63 6e 2f 73 61 64 73 78 63 64 73 2f 73 61 64 63 63 63 63 2f 53 6d 53 73 65 72 76 65 72 } //1 cn/sadsxcds/sadcccc/SmSserver
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}