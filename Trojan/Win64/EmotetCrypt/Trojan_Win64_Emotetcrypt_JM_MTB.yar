
rule Trojan_Win64_Emotetcrypt_JM_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 8a c5 83 c7 01 83 e0 3f 48 63 ef 49 03 c0 8a 04 10 32 01 48 83 c1 01 88 06 48 83 c6 01 49 3b ec 72 } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_2 = {73 4e 32 61 6b 26 37 5f 76 59 2b 5f 34 21 51 79 31 49 57 76 59 58 47 4d 4e 6b 40 63 7a 58 53 3e 65 29 4c 65 44 34 6b 3c 67 34 62 50 76 78 5a 72 66 5f 63 30 64 4c 6d 73 4a 65 6d 32 58 38 6f } //1 sN2ak&7_vY+_4!Qy1IWvYXGMNk@czXS>e)LeD4k<g4bPvxZrf_c0dLmsJem2X8o
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}