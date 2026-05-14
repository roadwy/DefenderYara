
rule Trojan_Win64_Tedy_AB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 89 c3 41 81 f3 ff ff ff ff 41 81 e3 14 d1 28 6f 41 81 e1 ff ff ff ff 44 09 d2 45 09 cb 44 31 da 83 f2 ff 41 89 c1 41 31 d1 41 21 c1 89 c2 83 f2 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Tedy_AB_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 b8 04 01 00 00 48 8d 95 b0 02 00 00 33 c9 ff 15 c9 3b 00 00 85 c0 74 7c c7 44 24 60 70 00 00 00 0f 57 c0 33 c0 0f 11 44 24 64 0f 11 44 24 74 0f 11 45 84 0f 11 45 94 0f 11 45 a4 0f 11 45 b4 48 89 45 c4 89 45 cc c7 44 24 64 40 04 00 00 48 8d 05 48 64 00 00 48 89 44 24 70 48 8d 85 b0 02 00 00 48 89 44 24 78 c7 45 90 01 00 00 00 48 8d 4c 24 60 ff 15 2d 3c 00 00 85 c0 74 18 48 8b 4d c8 48 85 c9 } //6
		$a_01_1 = {c7 44 24 60 70 00 00 00 0f 57 c0 33 c0 0f 11 44 24 64 0f 11 44 24 74 0f 11 45 84 0f 11 45 94 0f 11 45 a4 0f 11 45 b4 48 89 45 c4 89 45 cc c7 44 24 64 40 00 00 00 48 8d 05 ab 66 00 00 48 89 44 24 70 48 8d 05 af 66 00 00 48 89 44 24 78 48 8d 4d 20 e8 81 07 00 00 48 89 45 80 48 8d 4d 00 e8 74 07 00 00 48 89 45 88 c7 45 90 01 00 00 00 48 8d 4c 24 60 ff 15 16 3e 00 00 85 c0 } //6
		$a_81_2 = {53 63 72 65 65 6e 43 6f 6e 6e 65 63 74 } //6 ScreenConnect
		$a_81_3 = {22 20 2f 71 62 } //2 " /qb
		$a_81_4 = {69 6e 73 74 61 6c 6c 2e 72 65 73 2e 31 30 33 33 } //2 install.res.1033
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*6+(#a_81_2  & 1)*6+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=22
 
}