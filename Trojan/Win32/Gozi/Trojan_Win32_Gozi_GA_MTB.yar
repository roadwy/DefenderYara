
rule Trojan_Win32_Gozi_GA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 90 01 01 00 00 51 6a 00 ff 93 90 01 04 59 5e 89 83 90 01 04 89 c7 f3 a4 8b b3 90 01 04 8d bb 90 01 04 29 f7 01 f8 ff e0 90 00 } //1
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
		$a_02_0 = {0f b7 c0 80 e9 90 01 01 83 c0 90 01 01 89 35 90 02 04 8b 35 90 02 04 03 c2 89 44 24 90 01 01 83 c6 cb 8b 03 05 90 02 04 89 03 83 c3 04 a3 90 02 04 8b 44 24 90 01 01 03 c6 83 6c 24 90 01 01 01 8b 74 24 90 01 01 0f b7 c0 89 44 24 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 8b 55 f0 8b 45 fc 8d 8c 10 90 01 04 89 4d 90 01 01 8b 15 90 01 04 89 15 90 01 04 8b 45 90 01 01 a3 90 01 04 8b 4d 90 01 01 83 c1 90 01 01 89 4d 90 00 } //1
		$a_02_1 = {8b ff c7 05 90 02 20 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Gozi_GA_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c6 8d 7f 01 03 c1 a3 90 01 04 8a 44 3b ff 88 47 ff 80 3d 90 01 04 08 8b 15 90 01 04 0f b6 0d 90 01 04 74 90 01 01 c1 e1 90 01 01 2b ca eb 90 00 } //10
		$a_02_1 = {83 c2 f8 0f b7 c0 01 55 90 01 01 99 85 d2 72 90 01 01 77 90 01 01 3b c6 90 18 8b 7d 08 ff 55 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Gozi_GA_MTB_6{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c2 49 05 90 01 04 8a 00 88 82 90 01 04 42 85 db 77 90 01 01 72 90 01 01 83 fe 90 01 01 77 90 00 } //10
		$a_02_1 = {8b f0 83 c6 90 01 01 83 d2 ff 8b 4c 24 90 01 01 8b 5c 24 90 01 01 8b 44 24 90 01 01 03 de a3 90 01 04 8b 09 89 5c 24 90 01 01 3b d8 90 18 8b 44 24 0c 81 c1 90 01 04 8b 5c 24 90 01 01 03 de 89 0d 90 01 04 89 08 83 c0 04 83 6c 24 90 01 01 01 89 44 24 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}