
rule TrojanSpy_AndroidOS_SAgnt_BE_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.BE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 20 d0 00 21 00 6e 10 9e 00 01 00 0c 01 6e 10 af 0c 01 00 0c 01 14 00 02 00 02 01 6e 20 9b 0a 01 00 0c 01 1f 01 43 02 12 00 71 40 c0 24 13 20 0c 01 11 01 } //1
		$a_01_1 = {63 00 a4 0b 38 00 29 00 54 30 75 0b 38 00 25 00 54 30 4b 0b 38 00 21 00 54 31 52 0b 38 01 1d 00 71 20 fa 27 10 00 0c 00 6e 10 fc 27 00 00 38 04 11 00 54 34 57 0b 6e 10 42 28 04 00 0c 04 22 01 fa 04 70 30 04 25 31 00 6e 20 ce 06 14 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}