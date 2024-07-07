
rule TrojanDropper_AndroidOS_Wroba_F_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Wroba.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {02 2a 08 d0 01 2a 0c d0 8a b9 02 68 09 49 d2 f8 9c 22 79 44 10 47 02 68 08 49 d2 f8 9c 22 79 44 10 47 02 68 04 49 d2 f8 9c 22 79 44 10 47 } //1
		$a_00_1 = {c2 6f 30 46 90 47 01 46 30 68 08 4a 09 4b d0 f8 84 50 7a 44 7b 44 30 46 a8 47 02 46 30 46 21 46 43 46 5d f8 04 8b } //1
		$a_00_2 = {19 f8 0b 10 dd e9 09 02 61 40 90 42 07 f8 b9 1c 04 d2 01 70 09 98 01 30 09 90 03 e0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}