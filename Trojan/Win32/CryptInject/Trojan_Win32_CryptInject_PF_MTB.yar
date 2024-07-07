
rule Trojan_Win32_CryptInject_PF_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {87 ff 8b 1c 0a 49 41 90 01 02 81 f3 90 01 04 49 41 87 ff 89 1c 08 49 41 90 01 02 83 c1 04 49 41 c1 e9 00 81 f9 90 01 02 00 00 75 d4 87 ff 49 41 ff e0 90 00 } //1
		$a_02_1 = {87 ff 49 41 8b 1c 0a c1 e6 00 87 ff 81 f3 90 01 04 c1 e6 00 49 41 89 1c 08 c1 e6 00 87 ff 83 c1 04 c1 e6 00 90 01 02 81 f9 90 01 02 00 00 75 d1 49 41 c1 e6 00 ff e0 90 00 } //1
		$a_02_2 = {87 ff 49 41 c1 e6 00 8b 1c 0a c1 e6 00 87 ff 81 f3 90 01 04 c1 e6 00 49 41 89 1c 08 c1 e6 00 87 ff 83 c1 04 c1 e6 00 90 01 02 81 f9 90 01 02 00 00 75 d0 49 41 c1 e6 00 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule Trojan_Win32_CryptInject_PF_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.PF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 33 d2 8b c7 f7 74 24 20 8b 44 24 14 8a 0c 50 30 0c 1f 47 3b fd 75 95 } //1
		$a_01_1 = {56 8b 74 24 10 85 f6 76 13 8b 44 24 08 8b 4c 24 0c 2b c8 8a 14 01 88 10 40 4e 75 f7 5e c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}