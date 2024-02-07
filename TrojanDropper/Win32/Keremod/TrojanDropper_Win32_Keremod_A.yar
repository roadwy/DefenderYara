
rule TrojanDropper_Win32_Keremod_A{
	meta:
		description = "TrojanDropper:Win32/Keremod.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c6 45 e1 44 c6 45 e2 65 c6 45 e3 73 c6 45 e4 63 c6 45 e5 72 c6 45 e6 69 c6 45 e7 70 c6 45 e8 74 c6 45 e9 6f c6 45 ea 72 c6 45 eb 54 c6 45 ec 61 c6 45 ed 62 c6 45 ee 6c c6 45 ef 65 88 5d f0 ff 15 90 01 04 3d 04 00 00 c0 75 90 01 01 ff 75 d4 6a 40 ff 15 90 00 } //0a 00 
		$a_02_1 = {6a 64 33 d2 59 f7 f1 8b f2 46 c1 e6 04 56 e8 90 01 04 8b c8 8b c6 89 4c 90 01 02 e8 90 01 04 53 8d 44 90 01 02 50 56 ff 74 90 01 02 57 ff 15 90 01 04 ff 74 90 00 } //01 00 
		$a_00_2 = {25 73 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 } //01 00  %s\drivers\%s.sys
		$a_00_3 = {73 63 2e 65 78 65 20 63 72 65 61 74 65 20 25 73 20 74 79 70 65 3d 20 6b 65 72 6e 65 6c } //01 00  sc.exe create %s type= kernel
		$a_00_4 = {35 44 34 32 34 33 34 45 2d 42 43 41 33 2d 34 30 36 31 2d 39 46 41 43 2d 43 33 41 42 45 45 30 42 38 32 45 43 } //00 00  5D42434E-BCA3-4061-9FAC-C3ABEE0B82EC
	condition:
		any of ($a_*)
 
}