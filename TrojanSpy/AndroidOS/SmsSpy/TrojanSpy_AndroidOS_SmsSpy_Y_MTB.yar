
rule TrojanSpy_AndroidOS_SmsSpy_Y_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 06 47 10 00 00 54 01 ac 0e 38 01 0b 00 63 02 9c 0e 39 02 07 00 54 11 22 0e 6e 10 bb 25 01 00 } //1
		$a_01_1 = {70 10 26 26 01 00 0c 00 54 00 e1 0e 54 00 6d 00 1f 00 65 01 6e 20 27 07 20 00 0c 02 6f 20 56 10 21 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}