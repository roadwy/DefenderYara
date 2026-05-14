
rule TrojanDropper_AndroidOS_Mamont_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Mamont.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {b0 42 b2 82 e2 02 02 08 6e 20 51 09 27 00 55 02 4d 02 12 04 01 25 07 32 54 03 4f 02 38 05 8f 00 6e 10 4c 03 00 00 0a 05 12 09 15 0a 00 40 38 05 08 00 6e 10 46 09 07 00 0a 05 c9 a5 28 02 } //1
		$a_01_1 = {82 99 c7 95 87 55 6e 10 9d 09 04 00 0a 09 6e 10 d1 09 00 00 0c 0a 6e 10 8c 09 0a 00 0a 0a 82 aa c7 a9 87 99 3a 05 56 00 3a 09 54 00 6e 10 a7 09 04 00 0a 0a 87 aa 54 0b 49 02 52 bb 1b 02 da 0b 0b 02 b0 ab b0 5b } //1
		$a_01_2 = {b1 cb b1 5b 82 b5 6e 10 d1 09 00 00 0c 0b 52 bb ea 04 54 0c 49 02 52 cc 1b 02 b1 cb b1 9b 82 b9 7f 5b 7f 9c 6e 30 19 09 ba 0c 6e 20 47 03 a0 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}