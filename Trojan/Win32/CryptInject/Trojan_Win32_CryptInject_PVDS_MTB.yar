
rule Trojan_Win32_CryptInject_PVDS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PVDS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 8b 74 24 1c 81 f6 a6 77 2b 37 8b 7c 24 08 88 14 07 01 f0 8b 74 24 10 39 f0 89 44 24 04 74 } //2
		$a_01_1 = {8b 45 dc c6 45 ef a8 8b 4d e4 8a 14 01 8b 75 e0 88 14 06 83 c0 01 c7 45 f0 d9 29 9a 95 8b 7d e8 39 f8 89 45 dc 75 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}