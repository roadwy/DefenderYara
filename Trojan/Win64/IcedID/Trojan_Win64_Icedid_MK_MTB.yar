
rule Trojan_Win64_Icedid_MK_MTB{
	meta:
		description = "Trojan:Win64/Icedid.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 88 04 1b 83 e1 07 8b 44 95 e0 49 ff c3 d3 c8 ff c0 89 44 95 e0 83 e0 07 8a c8 42 8b 44 85 e0 d3 c8 ff c0 42 89 44 85 e0 48 8b 5d c8 4c 3b 5d d0 73 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Icedid_MK_MTB_2{
	meta:
		description = "Trojan:Win64/Icedid.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 04 24 48 8b 4c 24 08 eb 21 48 ff c0 48 89 44 24 08 eb c4 eb ce 48 8b 44 24 30 48 89 04 24 eb 27 48 8b 44 24 40 48 ff c8 eb c4 8a 09 88 08 eb 23 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Icedid_MK_MTB_3{
	meta:
		description = "Trojan:Win64/Icedid.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 3c 08 8b 84 24 90 01 04 99 b9 90 01 04 f7 f9 48 63 ca 48 8b 84 24 90 01 04 0f b6 04 08 8b d7 33 d0 48 63 8c 24 90 01 04 48 8b 84 24 90 01 04 88 14 08 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Icedid_MK_MTB_4{
	meta:
		description = "Trojan:Win64/Icedid.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 44 6e 62 2e 64 6c 6c } //10 wDnb.dll
		$a_01_1 = {42 68 30 31 32 56 4c 4a 43 30 7a } //1 Bh012VLJC0z
		$a_01_2 = {43 68 41 78 54 6d 56 61 4c } //1 ChAxTmVaL
		$a_01_3 = {44 30 65 7a 77 51 32 6b 58 50 } //1 D0ezwQ2kXP
		$a_01_4 = {44 35 46 66 42 51 49 57 44 7a } //1 D5FfBQIWDz
		$a_01_5 = {4b 6e 79 79 58 47 4c 49 72 32 59 } //1 KnyyXGLIr2Y
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_Icedid_MK_MTB_5{
	meta:
		description = "Trojan:Win64/Icedid.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {5f 00 67 00 61 00 74 00 3d 00 } //1 _gat=
		$a_00_1 = {5f 00 67 00 61 00 3d 00 } //1 _ga=
		$a_00_2 = {5f 00 75 00 3d 00 } //1 _u=
		$a_00_3 = {5f 00 5f 00 69 00 6f 00 3d 00 } //1 __io=
		$a_00_4 = {5f 00 67 00 69 00 64 00 3d 00 } //1 _gid=
		$a_00_5 = {43 00 6f 00 6f 00 6b 00 69 00 65 00 3a 00 20 00 5f 00 5f 00 67 00 61 00 64 00 73 00 3d 00 } //1 Cookie: __gads=
		$a_01_6 = {6c 6f 61 64 65 72 5f 64 6c 6c 5f 36 34 2e 64 6c 6c } //1 loader_dll_64.dll
		$a_01_7 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}