
rule TrojanSpy_AndroidOS_Banker_W_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.W!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {92 04 01 03 d8 05 04 02 6e 30 94 03 46 05 0c 04 13 05 10 00 71 20 79 03 54 00 0c 04 6e 10 72 03 04 00 0a 04 4f 04 02 03 d8 03 03 01 28 e8 } //1
		$a_00_1 = {6f 30 e7 05 10 02 54 02 ad 02 6e 20 c6 00 21 00 0e 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}