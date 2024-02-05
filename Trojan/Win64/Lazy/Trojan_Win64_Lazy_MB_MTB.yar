
rule Trojan_Win64_Lazy_MB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {5b eb 01 23 41 5f eb 01 25 41 5e eb 02 15 d7 41 5d eb 03 1d 24 cb 41 5c eb 02 be 72 5e eb 03 05 58 f3 5f eb 01 43 fe 05 3b 04 00 00 eb 03 bf f9 11 e9 b3 01 00 00 eb 03 25 87 c2 4d 8b } //05 00 
		$a_01_1 = {4d 5a ef 08 d9 94 7f b3 d9 3f 5f 6b 4a c6 e4 9f 35 8d 93 55 01 79 cd 41 e5 00 6e 53 a5 81 2d c3 67 60 90 8c 0a ab 9e d5 45 70 69 b0 ab bf 5f 3a } //02 00 
		$a_01_2 = {52 65 67 69 73 74 65 72 45 76 65 6e 74 53 6f 75 72 63 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}