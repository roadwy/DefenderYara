
rule Trojan_Win64_CryptInject_ZAF_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ZAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 41 f7 f8 48 63 d2 48 8d 05 30 1a 02 00 0f be 14 10 41 89 c8 41 83 f0 ff 89 d0 44 21 c0 41 89 d1 41 83 f1 ff 41 89 c8 45 21 c8 44 09 c0 89 45 e0 e8 d8 40 01 00 8b 45 e0 88 c2 48 8b 45 f0 48 63 4d e4 88 14 08 48 8b 45 f0 48 63 4d e4 0f be 04 08 83 f8 00 75 02 } //1
		$a_01_1 = {89 c2 8b 45 fc 83 e0 01 89 c0 89 c1 48 8d 05 56 e0 01 00 33 14 88 48 63 4d f8 48 8d 05 b4 e4 01 00 89 14 88 8b 45 f8 89 45 f0 b9 67 66 2d bc e8 e1 60 01 00 89 c1 8b 45 f0 01 c8 89 45 f8 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}