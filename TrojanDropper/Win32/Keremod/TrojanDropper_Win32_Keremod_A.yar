
rule TrojanDropper_Win32_Keremod_A{
	meta:
		description = "TrojanDropper:Win32/Keremod.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {c6 45 e1 44 c6 45 e2 65 c6 45 e3 73 c6 45 e4 63 c6 45 e5 72 c6 45 e6 69 c6 45 e7 70 c6 45 e8 74 c6 45 e9 6f c6 45 ea 72 c6 45 eb 54 c6 45 ec 61 c6 45 ed 62 c6 45 ee 6c c6 45 ef 65 88 5d f0 ff 15 ?? ?? ?? ?? 3d 04 00 00 c0 75 ?? ff 75 d4 6a 40 ff 15 } //10
		$a_02_1 = {6a 64 33 d2 59 f7 f1 8b f2 46 c1 e6 04 56 e8 ?? ?? ?? ?? 8b c8 8b c6 89 4c ?? ?? e8 ?? ?? ?? ?? 53 8d 44 ?? ?? 50 56 ff 74 ?? ?? 57 ff 15 ?? ?? ?? ?? ff 74 } //10
		$a_00_2 = {25 73 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 } //1 %s\drivers\%s.sys
		$a_00_3 = {73 63 2e 65 78 65 20 63 72 65 61 74 65 20 25 73 20 74 79 70 65 3d 20 6b 65 72 6e 65 6c } //1 sc.exe create %s type= kernel
		$a_00_4 = {35 44 34 32 34 33 34 45 2d 42 43 41 33 2d 34 30 36 31 2d 39 46 41 43 2d 43 33 41 42 45 45 30 42 38 32 45 43 } //1 5D42434E-BCA3-4061-9FAC-C3ABEE0B82EC
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}