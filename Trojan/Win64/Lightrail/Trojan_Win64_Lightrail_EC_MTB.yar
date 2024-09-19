
rule Trojan_Win64_Lightrail_EC_MTB{
	meta:
		description = "Trojan:Win64/Lightrail.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 03 ce 48 ff c6 42 88 44 f1 3e 48 63 c2 49 3b c0 7c e0 8b 5d 9b 41 03 d8 eb 4c 45 8b cb 48 85 d2 7e 42 4c 8b 6d ef 4d 8b c3 4d 8b d5 41 83 e5 3f 49 c1 fa 06 4e 8d 1c ed 00 00 00 00 4d 03 dd 41 8a 04 38 41 ff c1 } //5
		$a_01_1 = {b9 00 00 01 00 48 89 44 24 30 41 b9 01 00 00 00 48 89 44 24 28 41 b8 00 10 00 00 48 89 44 24 20 } //5
		$a_01_2 = {56 47 41 75 74 68 2e 64 6c 6c } //2 VGAuth.dll
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2) >=7
 
}