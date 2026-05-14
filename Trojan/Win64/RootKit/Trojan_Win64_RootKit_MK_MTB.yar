
rule Trojan_Win64_RootKit_MK_MTB{
	meta:
		description = "Trojan:Win64/RootKit.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 06 00 00 "
		
	strings :
		$a_01_0 = {fd 05 c3 5d d6 97 cd a4 86 ac fa b2 5d 8e ac f3 } //15
		$a_01_1 = {ad 68 1d 28 43 48 15 18 d0 79 77 07 cb 23 55 } //15
		$a_01_2 = {b5 32 9a 3a 97 4b 7b 57 13 71 ef 6a fc 60 93 6c } //15
		$a_01_3 = {2e 64 61 74 61 00 00 00 b8 81 01 00 00 10 01 } //10
		$a_01_4 = {f8 2f 00 40 2a 00 00 00 70 50 00 c0 } //3
		$a_01_5 = {0b 02 0e 1d 00 fa 00 00 00 a8 01 } //2
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*15+(#a_01_2  & 1)*15+(#a_01_3  & 1)*10+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2) >=60
 
}