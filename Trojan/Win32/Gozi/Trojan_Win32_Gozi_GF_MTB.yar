
rule Trojan_Win32_Gozi_GF_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 f3 2b fe 25 [0-10] 81 6d [0-20] bb ?? ?? ?? ?? 81 45 [0-20] 8b 4d ?? 8b 55 ?? 8b c7 d3 e0 8b cf c1 e9 ?? 03 4d ?? 03 45 ?? 03 d7 33 c1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gozi_GF_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 0c 4e 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? eb [0-0f] 83 25 ?? ?? ?? ?? 00 80 ea ?? 6b c1 ?? 88 15 ?? ?? ?? ?? 2b 45 ?? a3 ?? ?? ?? ?? 0f b6 c2 83 c0 ?? 89 45 ?? ff 55 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GF_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8d 4b ?? 2b c8 1b d6 01 0d [0-04] 8d 48 ff 11 15 [0-04] 0f af d9 8b 4c 24 ?? 8b 39 8a c8 80 e9 ?? 00 0d [0-04] 81 7c 24 [0-05] 75 } //10
		$a_02_1 = {33 c9 2b e8 1b ce 01 2d [0-04] 0f b6 6c 24 ?? 11 0d [0-04] 4d 0f af 2d [0-04] 8b 4c 24 ?? 83 44 24 ?? 04 81 c7 [0-04] 89 39 8a 4c 24 ?? 02 c8 ff 4c 24 ?? 89 2d [0-04] 89 3d [0-04] 88 4c 24 ?? 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Gozi_GF_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_02_0 = {2b c6 89 75 ?? 29 55 ?? 8d 84 38 ?? ?? ?? ?? 89 55 ?? be ?? ?? ?? ?? 8d 7d ?? a5 a5 a5 8b 55 ?? 33 55 ?? 41 03 55 ?? 89 4d ?? 03 55 ?? d3 ea 85 d2 74 } //10
		$a_02_1 = {2b ca 03 f1 8b 4d ?? 89 37 89 4d ?? 83 c7 04 90 18 ff 4d ?? 75 } //10
		$a_80_2 = {32 30 32 31 } //2021  1
		$a_80_3 = {43 6f 6e 76 65 72 74 53 74 72 69 6e 67 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 54 6f 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 41 } //ConvertStringSecurityDescriptorToSecurityDescriptorA  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=22
 
}
rule Trojan_Win32_Gozi_GF_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {8d 7d d0 a5 a5 a5 8b 4d ?? 33 4d ?? 68 00 04 00 00 2b 4d ?? 03 4d ?? 8d 4c 11 ?? 8b 55 ?? 51 8d 0c 02 e8 ?? ?? ?? ?? 8b 4d ?? 8b 41 ?? 2b 41 ?? 81 45 ?? 00 10 00 00 03 41 ?? ff 45 ?? a3 ?? ?? ?? ?? 39 5d ?? 72 } //10
		$a_80_1 = {32 30 32 31 } //2021  1
		$a_80_2 = {43 6f 6e 76 65 72 74 53 74 72 69 6e 67 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 54 6f 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 41 } //ConvertStringSecurityDescriptorToSecurityDescriptorA  1
		$a_80_3 = {43 72 65 61 74 65 46 69 6c 65 4d 61 70 70 69 6e 67 57 } //CreateFileMappingW  1
		$a_80_4 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //MapViewOfFile  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}