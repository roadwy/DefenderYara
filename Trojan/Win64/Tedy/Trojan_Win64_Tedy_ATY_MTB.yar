
rule Trojan_Win64_Tedy_ATY_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 89 ca 41 8d 0c 18 42 32 4c 00 10 48 c1 fa 08 31 d1 4c 89 ca 49 c1 f9 18 48 c1 fa 10 31 d1 44 31 c9 42 88 4c 00 10 49 ff c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Tedy_ATY_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b d6 48 89 55 97 41 b8 ?? ?? ?? ?? 4c 89 45 9f 88 55 87 c7 45 a7 ?? ?? ?? ?? b1 14 80 f1 55 48 8d 5b 01 49 3b d0 73 1f 48 8d 42 01 48 89 45 97 48 8d 45 87 49 83 f8 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Tedy_ATY_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c8 05 88 43 40 48 85 d2 0f 84 54 01 00 00 48 83 7a 18 00 0f 84 39 01 00 00 48 8b 42 18 f0 83 00 01 48 8b 4b 30 48 85 c9 74 06 ff 15 c8 7d 01 00 4c 89 e9 e8 24 1d 00 00 48 8b 4b 28 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Tedy_ATY_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 e0 88 85 f0 14 00 00 0f 28 45 c0 0f 28 4d d0 0f 29 8d e0 14 00 00 0f 29 85 d0 14 00 00 31 c9 31 d2 49 89 f8 ff 15 14 49 01 00 } //1
		$a_01_1 = {48 8b d7 4c 8b 4d c7 4b 8b 8c cb 20 32 05 00 48 03 ca 8a 04 32 42 88 44 f9 3e ff c7 48 ff c2 48 63 c7 } //1
		$a_01_2 = {49 2b f6 4b 8b 8c eb 20 32 05 00 49 03 ce 42 8a 04 36 42 88 44 f9 3e ff c7 49 ff c6 48 63 c7 48 3b c2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}