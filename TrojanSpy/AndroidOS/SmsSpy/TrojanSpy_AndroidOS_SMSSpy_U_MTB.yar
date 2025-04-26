
rule TrojanSpy_AndroidOS_SMSSpy_U_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 20 fe 9f 10 00 0a 02 38 02 14 00 62 02 3b 56 71 00 4f a0 00 00 0b 03 71 20 89 9f 43 00 0c 03 6e 20 d4 a1 32 00 0c 02 6e 30 19 a0 10 02 0c 00 } //1
		$a_03_1 = {12 00 1a 01 ?? ?? 71 00 4b 07 00 00 0c 02 6e 10 3c 9e 02 00 0c 02 1a 03 ?? ?? 6e 30 19 a0 31 02 0c 01 1a 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}