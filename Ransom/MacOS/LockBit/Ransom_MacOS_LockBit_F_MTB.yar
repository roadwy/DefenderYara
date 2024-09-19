
rule Ransom_MacOS_LockBit_F_MTB{
	meta:
		description = "Ransom:MacOS/LockBit.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 10 0f b6 70 14 40 f6 c6 01 74 56 0f b6 70 17 83 e6 1f 48 83 c6 ef 0f 1f 00 48 83 fe 08 77 3c 48 8d 0d 93 2c 1d 00 ff 24 f1 } //1
		$a_01_1 = {76 2d 55 48 89 e5 48 83 ec 08 0f b6 48 17 83 e1 1f 48 83 f9 14 75 0a 48 8b 40 40 48 83 c4 08 5d c3 e8 16 ff ff ff 48 89 d8 48 83 c4 08 5d c3 48 89 44 24 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}