
rule Backdoor_MacOS_Macma_E_MTB{
	meta:
		description = "Backdoor:MacOS/Macma.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 31 c9 44 89 c9 48 8b 15 48 33 00 00 48 8b 35 49 33 00 00 48 89 45 d0 48 89 cf 48 89 75 b8 48 89 ce 48 8b 4d b8 e8 ?? ?? ?? ?? 45 31 c9 44 89 cf 41 b9 0c 00 00 00 44 89 ce 48 8d 4d e4 48 89 45 c8 48 89 ca } //1
		$a_01_1 = {31 c0 89 c7 b8 01 00 00 00 f2 0f 10 45 d0 f2 0f 11 45 e8 f2 0f 10 45 c8 f2 0f 11 45 e0 48 c7 45 c0 04 00 00 00 48 c7 45 b8 08 00 00 00 0f 28 05 c2 2d 00 00 f3 0f 7e 4d c0 66 0f 62 c8 66 0f 28 05 c1 2d 00 00 66 0f 5c c8 66 0f 7c c9 f2 0f 10 45 e8 f2 0f 59 c8 f2 0f 10 05 b8 2d 00 00 0f 28 d1 f2 0f 5c d0 f2 48 0f 2c ca } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}