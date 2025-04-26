
rule Trojan_MacOS_Nukesped_H_MTB{
	meta:
		description = "Trojan:MacOS/Nukesped.H!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {39 13 c0 b5 94 5e d1 44 10 0c 99 68 4c b4 47 0b a0 d0 d6 75 d8 f3 dc b6 5c a6 8a b3 2b d9 ff 8d 28 19 21 cc } //1
		$a_00_1 = {35 35 35 35 34 39 34 34 65 34 35 34 36 30 31 33 64 62 30 66 33 35 38 35 62 63 37 30 36 62 65 32 34 35 35 64 30 38 34 65 00 fe 91 3b 84 0b 01 ce 04 da a4 bd 1f e8 61 14 b4 4e 79 d1 92 0c ac d2 4b b0 0e 38 ad 3f 88 54 ec } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}