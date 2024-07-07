
rule Trojan_Win32_IcedId_VSK_MTB{
	meta:
		description = "Trojan:Win32/IcedId.VSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 46 00 41 81 f0 a0 00 00 00 8b fa 81 e9 51 6b 4f 00 81 c7 32 64 00 00 41 81 c1 4e 42 00 00 89 43 00 } //2
		$a_01_1 = {8b 44 24 30 8b 4c 24 58 0f af 4c 24 30 8d 04 85 1f 01 00 00 0f af 44 24 10 2b c8 0f af 4c 24 58 6a 48 58 2b c1 01 44 24 30 } //2
		$a_01_2 = {8b 44 24 24 2a ca 83 44 24 10 04 8d 14 19 2c 45 f6 d9 02 d0 81 c7 2c b0 15 01 8a c2 89 7d 00 } //2
		$a_01_3 = {8b 55 ec 31 ca c6 45 eb 16 89 55 ec 8b 4d e4 8b 55 f4 8a 65 eb 8a 1c 0a 28 e0 88 45 eb } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=2
 
}