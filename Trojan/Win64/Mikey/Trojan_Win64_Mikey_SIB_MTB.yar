
rule Trojan_Win64_Mikey_SIB_MTB{
	meta:
		description = "Trojan:Win64/Mikey.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 1f 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 69 63 65 4d 61 69 6e } //10 ServiceMain
		$a_00_1 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //10 svchost.exe
		$a_00_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //10 rundll32.exe
		$a_03_3 = {45 33 c9 43 8a 3c 11 49 ff c1 4d 3b c8 7d ?? 43 8a 34 11 49 ff c1 eb ?? 41 bc ?? ?? ?? ?? 4d 3b c8 7d ?? 43 8a 2c 11 49 ff c1 eb ?? bb ?? ?? ?? ?? 44 8a f7 40 80 e7 ?? 40 8a c6 c0 e8 ?? 40 c0 e7 ?? 40 8a ce 40 0a f8 80 e1 ?? 40 8a c5 c0 e8 ?? c0 e1 ?? 41 c0 ee ?? 0a c8 40 8a c5 24 ?? 45 85 e4 74 ?? b1 ?? eb ?? 0f b6 d0 85 db b8 ?? ?? ?? ?? 0f 45 d0 41 0f b6 c6 4c 8d 35 ?? ?? ?? ?? 0f b6 c9 42 8a 04 30 41 83 c3 04 41 88 45 ?? 40 0f b6 c7 49 83 c5 ?? 42 8a 04 30 41 88 45 ?? 42 8a 0c 31 41 88 4d ?? 0f b6 ca ba ?? ?? ?? ?? 42 8a 0c 31 41 88 4d ?? 4d 3b c8 0f 8c } //1
		$a_03_4 = {48 8b f2 4c 8b f9 4d 63 f0 48 8d 2d ?? ?? ?? ?? 44 8b ef 43 0f b6 54 3d ?? 48 8b cd ff 15 ?? ?? ?? ?? 43 0f b6 54 3d ?? 48 8b cd 48 8b d8 40 2a dd ff 15 ?? ?? ?? ?? 43 0f b6 54 3d ?? 4c 8b e0 48 8b cd 44 2a e5 ff 15 ?? ?? ?? ?? 43 0f b6 54 3d ?? 48 8b e8 48 8d 05 ?? ?? ?? ?? 48 8b c8 40 2a e8 ff 15 ?? ?? ?? ?? c0 e3 ?? 40 8a cd 4c 8b d8 48 8d 05 ?? ?? ?? ?? c0 e1 06 44 2a d8 41 8a c4 49 83 c5 ?? c0 e8 ?? 41 0a cb ff c7 0a c3 88 06 48 ff c6 40 80 fd ?? 74 ?? 40 c0 ed ?? 41 c0 e4 ?? ff c7 41 0a ec 40 88 2e 48 ff c6 41 80 fb ?? 74 ?? 88 0e ff c7 48 ff c6 48 8d 2d ?? ?? ?? ?? 4d 3b ?? 0f 8c } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=31
 
}