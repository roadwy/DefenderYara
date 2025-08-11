
rule Trojan_Linux_SAgnt_X_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.X!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 1d 8d e2 30 10 81 e2 01 2a a0 e3 05 00 a0 e1 8d 26 00 eb 81 1d 8d e2 30 10 81 e2 00 20 50 e2 04 00 a0 e1 f4 ff ff ca 05 00 a0 e1 35 26 00 eb 04 00 a0 e1 33 26 00 eb 08 10 8d e2 70 00 8d e2 73 15 00 eb 01 00 70 e3 75 ff ff 0a 41 0d 8d e2 18 10 9d e5 30 00 80 e2 63 15 00 eb 01 00 70 e3 } //1
		$a_01_1 = {00 20 93 e5 01 00 52 e3 f9 ff ff 1a 08 c0 93 e5 14 20 93 e5 0c 00 50 e1 02 20 8c e0 0c 00 a0 21 20 30 83 e2 02 00 51 e1 02 10 a0 31 0e 00 53 e1 f2 ff ff 3a ff 3e 81 e2 0f 30 83 e2 ff 3e c3 e3 ff 6e c0 e3 0f 30 c3 e3 0f 60 c6 e3 03 60 66 e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}