
rule Trojan_Win32_Gepys_B{
	meta:
		description = "Trojan:Win32/Gepys.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d d5 c6 dd c3 75 04 b0 01 eb 32 3d 10 5f e3 b4 74 f5 3d d1 ed 7a 26 } //1
		$a_03_1 = {c7 45 fc 20 37 ef c6 c7 45 f4 20 00 00 00 ff 75 10 ff 75 fc 57 6a 0b 59 e8 ?? ?? ?? ?? ff 75 10 81 45 fc 47 86 c8 61 } //1
		$a_01_2 = {0f b7 46 24 8b 4e 28 d1 e8 85 c9 74 20 85 c0 74 1c 8d 54 41 fe 66 83 3a 5c 74 06 83 ea 02 48 75 f4 8d 04 41 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Gepys_B_2{
	meta:
		description = "Trojan:Win32/Gepys.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {bb 20 37 ef c6 c7 45 fc 20 00 00 00 ff 75 0c 53 57 6a 0b 59 e8 ?? ?? ?? ?? ff 75 0c 81 c3 47 86 c8 61 } //1
		$a_01_1 = {81 7d f4 4d 4f 44 53 75 3c 8b 75 f8 56 e8 } //1
		$a_03_2 = {4e 8b ca 83 f9 0a 72 03 83 c1 27 80 c1 30 88 4c 35 ?? 85 c0 75 } //1
		$a_03_3 = {6c 6f 77 5c 00 00 00 00 6b 62 64 6f ?? ?? ?? 2e 74 6d 70 } //1
		$a_03_4 = {47 45 54 20 ?? ?? ?? ?? 50 4f 53 54 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 0a 68 6f 73 74 3a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Gepys_B_3{
	meta:
		description = "Trojan:Win32/Gepys.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {0f cf 0f ce c7 45 fc 20 37 ef c6 c7 45 f4 20 00 00 00 } //1
		$a_01_1 = {81 45 fc 47 86 c8 61 ff 75 fc 2b f0 56 33 c9 e8 } //1
		$a_01_2 = {6a 07 5e 33 d2 6a 1a 5f f7 f7 83 c2 61 66 89 11 83 c1 02 4e 75 ed } //1
		$a_03_3 = {03 c3 50 8d 45 ?? 50 8d 45 ?? 50 56 6a 01 56 57 89 75 ?? c7 45 ?? 00 10 00 00 ff 15 } //1
		$a_01_4 = {5c 00 53 00 68 00 65 00 6c 00 6c 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 00 00 00 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 00 00 00 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 00 00 } //1
		$a_01_5 = {2e 00 74 00 6d 00 70 00 00 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_01_6 = {2e 00 65 00 78 00 65 00 00 00 00 00 00 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 00 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 47 00 75 00 69 00 64 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
rule Trojan_Win32_Gepys_B_4{
	meta:
		description = "Trojan:Win32/Gepys.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {81 ea 47 86 c8 61 8b f2 c1 ee 0b 83 e6 03 8b 34 b7 } //1
		$a_01_1 = {0f c9 0f c8 ba 20 37 ef c6 c7 45 fc 20 00 00 00 } //1
		$a_01_2 = {b8 4f ec c4 4e f7 e6 c1 ea 03 8b c2 6b c0 1a 2b f0 83 c6 61 66 89 71 02 } //1
		$a_03_3 = {03 d3 52 8d 45 ?? 50 8d 4d ?? 51 56 6a 01 56 57 89 75 ?? c7 45 ?? 00 10 00 00 ff 15 } //1
		$a_01_4 = {5c 00 53 00 68 00 65 00 6c 00 6c 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 00 00 00 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 00 00 00 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 00 00 } //1
		$a_01_5 = {2e 00 74 00 6d 00 70 00 00 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_01_6 = {2e 00 65 00 78 00 65 00 00 00 00 00 00 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 00 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 47 00 75 00 69 00 64 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
rule Trojan_Win32_Gepys_B_5{
	meta:
		description = "Trojan:Win32/Gepys.B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d d5 c6 dd c3 75 04 b0 01 eb 32 3d 10 5f e3 b4 74 f5 3d d1 ed 7a 26 } //1
		$a_03_1 = {c7 45 fc 20 37 ef c6 c7 45 f4 20 00 00 00 ff 75 10 ff 75 fc 57 6a 0b 59 e8 ?? ?? ?? ?? ff 75 10 81 45 fc 47 86 c8 61 } //1
		$a_01_2 = {0f b7 46 24 8b 4e 28 d1 e8 85 c9 74 20 85 c0 74 1c 8d 54 41 fe 66 83 3a 5c 74 06 83 ea 02 48 75 f4 8d 04 41 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}