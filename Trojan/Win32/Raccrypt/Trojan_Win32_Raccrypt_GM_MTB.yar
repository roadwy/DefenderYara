
rule Trojan_Win32_Raccrypt_GM_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 0f 82 } //1
		$a_02_1 = {33 44 24 04 c2 ?? 00 81 00 40 36 ef c6 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 03 d0 c1 ?? 04 03 45 ?? c1 ?? 05 03 4d ?? 52 89 3d [0-04] 90 18 33 44 24 04 c2 ?? 00 81 00 40 36 ef c6 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 66 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 72 00 6e 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05 ?? ?? ?? ?? 6c 00 6c 00 a3 ?? ?? ?? ?? ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b [0-14] c1 ?? 04 03 [0-1e] c1 ?? 05 03 [0-0f] 33 } //1
		$a_00_1 = {33 44 24 04 c2 04 00 81 00 f5 34 ef c6 c3 } //1
		$a_00_2 = {33 44 24 04 c2 04 00 81 00 f4 34 ef c6 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 3c 00 c1 ?? 04 03 [0-04] c1 [0-01] 05 03 [0-06] 33 ?? 33 } //10
		$a_02_1 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 3c 00 c1 ?? 05 03 [0-06] 68 b9 79 37 9e [0-06] 33 [0-06] 33 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 55 7b 11 c7 [0-05] 8e e6 d8 1e c7 [0-05] 7b 0c db 13 c7 [0-05] a6 c3 f8 4a c7 [0-05] 51 b7 cd 49 c7 [0-05] 29 66 56 72 c7 [0-05] ed ?? ?? 49 c7 [0-05] 18 61 f3 05 } //1
		$a_02_1 = {a5 28 36 47 c7 [0-05] b7 e0 73 4c c7 [0-05] 02 97 13 70 c7 [0-05] 0d d2 eb 21 c7 [0-05] 05 3d e8 27 c7 [0-05] 86 38 39 19 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {50 6a 40 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15 } //1
		$a_02_1 = {f6 56 ff 35 ?? ?? ?? ?? 66 c7 05 ?? ?? ?? ?? 61 6c 66 c7 05 ?? ?? ?? ?? 65 63 c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 72 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}