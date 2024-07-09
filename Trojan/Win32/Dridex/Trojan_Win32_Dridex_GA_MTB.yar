
rule Trojan_Win32_Dridex_GA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 66 3b cf 74 ?? 0f b7 10 0f af d6 8a ca 8b f2 2a cb 89 35 ?? ?? ?? ?? 2a 4c 24 ?? 8a d9 0f b7 cd 3b d1 74 ?? 83 c0 02 3d ?? ?? ?? ?? 7c } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Dridex_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 f6 5b fe c5 47 39 f0 89 45 ?? 89 4d ?? 89 55 [0-30] 8b 45 ?? 8b 4d ?? 8a 55 ?? 88 14 01 83 c0 ?? 8b 75 ?? 39 f0 89 45 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 3a 5c 57 6f 72 6b 5c 5f 62 69 6e 5c 52 65 6c 65 61 73 65 2d 57 69 6e 33 32 5c 6c 64 72 2e 70 64 62 } //S:\Work\_bin\Release-Win32\ldr.pdb  10
		$a_80_1 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  1
		$a_80_2 = {44 65 62 75 67 42 72 65 61 6b } //DebugBreak  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}
rule Trojan_Win32_Dridex_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 23 00 cc cc [0-01] cc } //10
		$a_02_1 = {29 df 89 fb 88 dc 88 64 24 ?? 8b 7d ?? 8b 5d ?? 8a 64 24 ?? 88 24 3b 66 8b 7c 24 ?? 66 89 7c 24 ?? 88 44 24 } //5
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*5) >=10
 
}
rule Trojan_Win32_Dridex_GA_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 1e 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 90 0a 23 00 cc cc cc eb } //10
		$a_01_1 = {4d 00 59 00 41 00 50 00 50 00 2e 00 45 00 58 00 45 00 } //10 MYAPP.EXE
		$a_01_2 = {73 00 65 00 6c 00 66 00 2e 00 65 00 78 00 65 00 } //10 self.exe
		$a_01_3 = {57 00 6e 00 65 00 65 00 64 00 73 00 77 00 68 00 69 00 63 00 68 00 47 00 68 00 6f 00 73 00 74 00 65 00 72 00 79 00 78 00 41 00 44 00 } //10 WneedswhichGhosteryxAD
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=30
 
}
rule Trojan_Win32_Dridex_GA_MTB_6{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 ea 01 2b 55 ?? 89 15 ?? ?? ?? ?? 0f b7 45 ?? 0f af 05 ?? ?? ?? ?? 2b 45 ?? 66 89 45 ?? 0f b7 4d ?? 0f af 0d ?? ?? ?? ?? 2b 4d ?? 66 89 4d ?? 0f b7 55 ?? 8b 45 ?? 8d 8c 10 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 75 ?? 81 c2 ?? ?? ?? ?? 83 c6 03 83 ee 03 81 c2 ?? ?? ?? ?? ff e6 } //10
		$a_02_1 = {64 a1 00 00 00 00 50 83 c4 f0 53 56 57 a1 ?? ?? ?? ?? 31 45 ?? 33 c5 50 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_GA_MTB_7{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_02_0 = {89 fa 81 f2 ?? ?? ?? ?? 89 54 24 ?? 89 5c 24 ?? 0f b6 04 08 89 c1 0f b6 55 ?? 29 d0 88 c5 89 5c 24 ?? 89 7c 24 ?? 88 6c 24 ?? 8b 45 ?? 8b 55 ?? 8a 6c 24 ?? 80 f1 ff 88 4c 24 ?? 88 2c 10 89 74 24 ?? 8d 65 } //10
		$a_02_1 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 } //10
		$a_80_2 = {74 74 74 74 33 32 } //tttt32  10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10) >=30
 
}
rule Trojan_Win32_Dridex_GA_MTB_8{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {72 65 73 75 6c 74 73 73 74 61 74 65 6d 65 6e 74 6b 69 6c 6c 65 72 66 65 61 74 75 72 65 73 54 68 65 } //resultsstatementkillerfeaturesThe  1
		$a_80_1 = {32 30 31 35 61 73 73 68 6f 6c 65 74 79 70 65 64 } //2015assholetyped  1
		$a_80_2 = {62 61 74 6d 61 6e 49 38 66 69 6c 65 73 29 51 7a 46 6f 72 } //batmanI8files)QzFor  1
		$a_80_3 = {4c 32 30 30 38 2c 72 61 6e 64 6f 6c 75 63 6b 79 59 } //L2008,randoluckyY  1
		$a_80_4 = {74 68 72 65 65 41 6d 65 61 6e 69 6e 67 4c 69 6e 75 78 65 79 } //threeAmeaningLinuxey  1
		$a_80_5 = {4d 5a 62 75 74 78 6d 74 61 69 74 6b } //MZbutxmtaitk  1
		$a_80_6 = {73 70 65 65 64 79 76 63 72 69 63 6b 65 74 66 61 69 6c 65 64 2e 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c } //speedyvcricketfailed.International  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=6
 
}