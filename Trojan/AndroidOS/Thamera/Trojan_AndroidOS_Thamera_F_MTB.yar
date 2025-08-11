
rule Trojan_AndroidOS_Thamera_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Thamera.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 20 c0 29 51 00 0c 08 1f 08 47 01 6e 10 28 06 08 00 0c 09 1f 09 2d 02 52 9d d6 00 b1 7d 52 97 d7 00 b1 27 12 02 71 20 23 28 d2 00 0a 09 71 20 23 28 72 00 0a 0e 7b dd 71 20 23 28 d2 00 0a 0d 7b 77 71 20 23 28 72 00 0a 07 6e 10 31 06 08 00 0a 08 b0 98 b0 e8 b0 86 d8 05 05 01 01 72 01 d7 } //1
		$a_01_1 = {12 03 6e 20 26 07 30 00 0c 01 6e 10 31 06 01 00 0a 03 6e 10 2e 06 01 00 0a 05 db 04 04 02 db 06 03 02 b1 64 db 06 05 02 b1 62 b0 43 b0 25 6e 55 79 06 41 32 0e 00 df 03 09 01 b1 3a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}