
rule TrojanDropper_AndroidOS_Wroba_H_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Wroba.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {88 02 40 f9 e2 00 00 b0 e3 00 00 b0 e1 03 00 aa 08 85 40 f9 42 bc 16 91 63 e4 16 91 e0 03 14 aa 00 01 3f d6 e2 03 00 aa e0 03 14 aa e1 03 13 aa fd 7b 42 a9 f4 4f 41 a9 e3 03 15 aa } //1
		$a_00_1 = {08 00 40 f9 e1 00 00 f0 21 c4 01 91 02 9d 42 f9 40 00 1f d6 08 00 40 f9 e1 00 00 b0 21 ec 10 91 02 9d 42 f9 40 00 1f d6 08 00 40 f9 e1 00 00 b0 21 c0 10 91 02 9d 42 f9 40 00 1f d6 } //1
		$a_00_2 = {e9 23 44 a9 0a 6b 77 38 3f 01 08 eb 53 01 15 4a c2 00 00 54 33 01 00 39 e8 23 40 f9 08 05 00 91 e8 23 00 f9 21 00 00 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}