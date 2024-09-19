
rule Trojan_Win32_Tedy_MBXT_MTB{
	meta:
		description = "Trojan:Win32/Tedy.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 20 36 40 00 fc 31 40 00 } //3
		$a_01_1 = {40 1c 40 00 17 f8 b0 00 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 01 00 e9 00 00 00 a0 18 40 00 90 1a 40 00 3c 11 40 00 78 00 00 00 80 00 00 00 87 } //2
		$a_01_2 = {76 79 69 6d 67 77 75 00 75 74 77 6f 6c 6f 00 00 b9 a4 b3 cc 31 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}