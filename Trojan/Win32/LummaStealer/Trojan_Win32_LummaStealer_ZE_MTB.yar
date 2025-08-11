
rule Trojan_Win32_LummaStealer_ZE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 34 c1 c3 0c 01 c8 05 4e fd 53 a9 89 04 24 01 eb c1 c2 0a 89 f8 31 d0 21 d8 31 d0 03 6c 24 40 01 e8 05 e9 76 6d 7a c1 c0 05 01 f0 c1 c7 0a 89 d9 31 f9 21 c1 31 f9 8b 6c 24 54 01 ee 01 f1 81 c1 e9 76 6d 7a c1 c1 0f 01 d1 c1 c3 0a 89 c6 31 de 21 ce 31 de 03 54 24 30 01 f2 81 c2 e9 76 6d 7a c1 c2 08 01 fa 03 7c 24 1c c1 c0 0a 89 ce 31 c6 31 d6 01 f7 c1 c7 08 01 df 03 5c 24 34 c1 c1 0a 89 d6 31 ce 31 fe 01 f3 c1 c3 05 01 c3 01 e8 c1 c2 0a 89 fe 31 d6 31 de 01 f0 c1 c0 0c 01 c8 03 4c 24 2c c1 c7 0a 89 de 31 fe 31 c6 01 f1 c1 c1 09 01 d1 03 54 24 24 c1 c3 0a 89 c6 31 de 31 ce 01 f2 c1 c2 0c 01 fa 03 7c } //1
		$a_01_1 = {24 3c c1 c0 0a 89 ce 31 c6 31 d6 01 f7 c1 c7 05 01 df 03 5c 24 38 c1 c1 0a 89 d6 31 ce 31 fe 01 f3 c1 c3 0e 01 c3 03 44 24 40 c1 c2 0a 89 fe 31 d6 31 de 01 f0 c1 c0 06 01 c8 03 4c 24 44 c1 c7 0a 89 de 31 fe 31 c6 01 f1 c1 c1 08 01 d1 03 54 24 48 c1 c3 0a 89 c6 31 de 31 ce 01 f2 8b 34 24 c1 c6 05 8b 6c 24 04 01 ee 89 34 24 8b 74 24 58 01 f5 89 6c 24 04 c1 c2 0d 01 fa 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}