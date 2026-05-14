
rule Trojan_MacOS_Amos_EY_MTB{
	meta:
		description = "Trojan:MacOS/Amos.EY!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c3 48 b8 fd 3c 65 7d 0f 45 eb 75 48 8d b4 24 20 3e 00 00 48 89 06 48 b8 43 85 49 b9 cb f3 cd b3 48 89 46 08 48 b8 18 d4 a5 87 4d 65 f2 a3 48 89 46 10 48 b8 6a be bc a4 f1 de 98 12 48 89 46 18 48 8d 84 24 80 2f 00 00 48 8b 4c 24 18 48 89 08 48 8b 4c 24 20 48 89 48 08 48 8b 4c 24 50 48 89 48 10 48 8b 4c 24 58 48 89 48 18 c5 fd 6f 00 c5 fd ef 06 c5 fd 7f 06 } //1
		$a_01_1 = {c6 05 93 c5 02 00 01 b1 01 80 3d 89 c5 02 00 01 75 55 48 8b 05 70 a5 02 00 48 89 84 24 80 2f 00 00 8b 15 6a a5 02 00 48 85 d2 74 34 31 c9 48 8d 35 54 a5 02 00 89 cf 83 e7 07 40 8a bc 3c 80 2f 00 00 40 30 7c 31 10 48 d1 c8 48 89 84 24 80 2f 00 00 48 ff c1 48 39 ca } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}