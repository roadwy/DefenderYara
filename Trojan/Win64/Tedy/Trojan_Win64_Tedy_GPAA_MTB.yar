
rule Trojan_Win64_Tedy_GPAA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 14 56 31 c8 0f b6 d8 48 8d 44 24 2c } //3
		$a_81_1 = {64 65 5f 78 6f 72 } //1 de_xor
		$a_81_2 = {64 65 5f 52 63 34 } //1 de_Rc4
		$a_81_3 = {64 65 5f 41 65 73 } //1 de_Aes
		$a_81_4 = {64 65 5f 41 65 73 52 63 34 58 6f 72 } //1 de_AesRc4Xor
	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}