
rule Trojan_Win32_Dridex_DD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {44 6f 6f 72 72 6c 65 64 46 67 70 70 72 } //DoorrledFgppr  3
		$a_80_1 = {47 70 65 72 6e 66 65 64 65 65 66 65 2e 70 64 62 } //Gpernfedeefe.pdb  3
		$a_80_2 = {53 65 6c 66 20 65 78 } //Self ex  3
		$a_80_3 = {4d 70 72 49 6e 66 6f 42 6c 6f 63 6b 52 65 6d 6f 76 65 } //MprInfoBlockRemove  3
		$a_80_4 = {74 65 73 74 61 70 70 2e 65 78 65 } //testapp.exe  3
		$a_80_5 = {4a 65 74 53 65 65 6b } //JetSeek  3
		$a_80_6 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //GetTempFileNameA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_DD_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 16 01 d1 8b 55 ?? 81 ea ?? ?? ?? ?? 89 c8 89 55 ?? 99 8b 4d ?? f7 f9 8b 75 ?? 89 16 8b 55 ?? 8b 0a 8b 55 ?? 8b 12 0f b6 0c 0a 8b 16 8b 75 ?? 8b 36 0f b6 14 16 31 d1 8b 55 ?? 8b 32 8b 55 c4 8b 12 88 0c 32 } //1
		$a_03_1 = {0f b6 14 16 8b 75 ?? 8b 7d ?? 0f b6 34 37 01 f2 89 d0 99 f7 f9 89 55 ?? 8b 55 ?? 8b 75 ?? 0f b6 14 16 8b 75 ?? 8b 7d ?? 0f b6 34 37 31 f2 88 d3 8b 55 ?? 8b 75 ?? 88 1c 16 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_DD_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 a9 00 00 00 8b 4d ?? 66 89 01 8b 55 ?? 0f b7 02 83 e8 40 8b 4d ?? 66 89 01 ba ae 00 00 00 8b 45 ?? 66 89 50 02 8b 4d ?? 0f b7 51 02 83 ea 40 8b 45 ?? 66 89 50 02 b9 b4 00 00 00 8b 55 ?? 66 89 4a 04 8b 45 ?? 0f b7 48 04 83 e9 40 8b 55 ?? 66 89 4a 04 b8 a5 00 00 00 8b 4d ?? 66 89 41 06 8b 55 ?? 0f b7 42 06 83 e8 40 8b 4d ?? 66 89 41 06 ba b2 00 00 00 8b 45 ?? 66 89 50 08 8b 4d ?? 0f b7 51 08 83 ea 40 8b 45 ?? 66 89 50 08 b9 a6 00 00 00 8b 55 ?? 66 89 4a 0a 8b 45 ?? 0f b7 48 0a 83 e9 40 8b 55 ?? 66 89 4a 0a b8 a1 00 00 00 8b 4d ?? 66 89 41 0c 8b 55 ?? 0f b7 42 0c 83 e8 40 8b 4d ?? 66 89 41 0c } //1
		$a_02_1 = {83 ea 40 8b 45 ?? 66 89 50 4a b9 a1 00 00 00 8b 55 ?? 66 89 4a 4c 8b 45 ?? 0f b7 48 4c 83 e9 40 8b 55 ?? 66 89 4a 4c b8 70 00 00 00 8b 4d ?? 66 89 41 4e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}