
rule Trojan_Win32_Gozi_GA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 ?? 00 00 51 6a 00 ff 93 ?? ?? ?? ?? 59 5e 89 83 ?? ?? ?? ?? 89 c7 f3 a4 8b b3 ?? ?? ?? ?? 8d bb ?? ?? ?? ?? 29 f7 01 f8 ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gozi_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_00_0 = {c0 c8 07 68 cd 1b 02 10 c3 } //5
		$a_00_1 = {34 0d 68 98 ec 01 10 c3 } //5
		$a_00_2 = {68 2d ad 01 10 68 2d ad 01 10 b8 7c c3 01 10 ff d0 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //VirtualProtectEx  1
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}
rule Trojan_Win32_Gozi_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c0 80 e9 ?? 83 c0 ?? 89 35 [0-04] 8b 35 [0-04] 03 c2 89 44 24 ?? 83 c6 cb 8b 03 05 [0-04] 89 03 83 c3 04 a3 [0-04] 8b 44 24 ?? 03 c6 83 6c 24 ?? 01 8b 74 24 ?? 0f b7 c0 89 44 24 ?? 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 8b 55 f0 8b 45 fc 8d 8c 10 ?? ?? ?? ?? 89 4d ?? 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 ?? a3 ?? ?? ?? ?? 8b 4d ?? 83 c1 ?? 89 4d } //1
		$a_02_1 = {8b ff c7 05 [0-20] 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Gozi_GA_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c6 8d 7f 01 03 c1 a3 ?? ?? ?? ?? 8a 44 3b ff 88 47 ff 80 3d ?? ?? ?? ?? 08 8b 15 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 74 ?? c1 e1 ?? 2b ca eb } //10
		$a_02_1 = {83 c2 f8 0f b7 c0 01 55 ?? 99 85 d2 72 ?? 77 ?? 3b c6 90 18 8b 7d 08 ff 55 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Gozi_GA_MTB_6{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c2 49 05 ?? ?? ?? ?? 8a 00 88 82 ?? ?? ?? ?? 42 85 db 77 ?? 72 ?? 83 fe ?? 77 } //10
		$a_02_1 = {8b f0 83 c6 ?? 83 d2 ff 8b 4c 24 ?? 8b 5c 24 ?? 8b 44 24 ?? 03 de a3 ?? ?? ?? ?? 8b 09 89 5c 24 ?? 3b d8 90 18 8b 44 24 0c 81 c1 ?? ?? ?? ?? 8b 5c 24 ?? 03 de 89 0d ?? ?? ?? ?? 89 08 83 c0 04 83 6c 24 ?? 01 89 44 24 ?? 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}