
rule TrojanSpy_AndroidOS_SAgnt_BC_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.BC!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 0c 43 00 70 10 c9 00 0c 00 22 08 43 00 70 10 c9 00 08 00 6e 10 45 01 0b 00 0a 09 b7 19 6e 20 37 01 8b 00 6e 20 38 01 cb 00 23 db 4a 01 71 10 a5 01 09 00 0c 0a 4d 0a 0b 02 6e 10 cb 00 08 00 0a 0a } //1
		$a_01_1 = {22 00 41 00 70 10 c4 00 00 00 62 01 2a 00 6e 20 c8 00 10 00 6e 30 c6 00 40 05 60 04 9f 00 a7 04 06 04 71 10 ca 01 04 00 0a 04 60 05 a1 00 a7 05 07 05 71 10 ca 01 05 00 0a 05 15 01 00 40 2d 04 04 01 3b 04 06 00 2d 04 05 01 3a 04 13 00 60 04 9f 00 60 05 a1 00 a6 02 06 04 c9 12 a6 03 07 05 c9 13 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}