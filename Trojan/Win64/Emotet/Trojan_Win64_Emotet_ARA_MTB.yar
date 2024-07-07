
rule Trojan_Win64_Emotet_ARA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 8d 40 01 f7 e6 8b c6 ff c6 c1 ea 05 8d 0c 52 c1 e1 04 2b c1 48 63 c8 42 0f b6 04 11 43 32 44 07 ff 41 88 40 ff 41 3b f4 72 d0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_Emotet_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 41 ff c0 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 2c 2b c8 48 63 c1 48 8d 0d c9 60 08 00 8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 c7 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_Emotet_ARA_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 8d 0c 92 c1 e1 03 2b c1 48 63 c8 48 8d 05 be 74 08 00 8a 04 01 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 c4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_Emotet_ARA_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b c0 41 83 c0 01 99 83 e2 1f 03 c2 83 e0 1f 2b c2 48 63 c8 48 8d 05 03 c8 08 00 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 01 44 3b c6 72 d1 } //2
		$a_01_1 = {73 63 2e 65 78 65 } //2 sc.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win64_Emotet_ARA_MTB_5{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 38 ff c0 89 44 24 38 8b 44 24 68 39 44 24 38 73 42 48 63 44 24 38 48 8b 4c 24 60 0f b6 04 01 89 44 24 40 8b 44 24 38 99 b9 2e 00 00 00 f7 f9 8b c2 48 98 48 8b 4c 24 28 0f b6 04 01 8b 4c 24 40 33 c8 8b c1 48 63 4c 24 38 48 8b 54 24 30 88 04 0a eb aa } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win64_Emotet_ARA_MTB_6{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b c8 b8 79 78 78 78 41 f7 e8 41 ff c0 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 11 2b c8 48 63 c1 48 8d 0d b7 de 07 00 8a 04 08 42 32 04 16 41 88 02 49 ff c2 44 3b c5 72 c7 } //10
		$a_01_1 = {41 8b c8 b8 b7 60 0b b6 41 f7 e8 41 03 d0 41 ff c0 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 2d 2b c8 48 63 c1 48 8d 0d 04 f4 07 00 8a 04 08 42 32 04 16 41 88 02 49 ff c2 44 3b c5 72 c4 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}