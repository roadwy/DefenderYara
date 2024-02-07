
rule Backdoor_Win32_Tapazom_A{
	meta:
		description = "Backdoor:Win32/Tapazom.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 01 ffffffdc 00 0a 00 00 64 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 03 00 00 00 8d 75 f4 33 db 8d 45 ec 8b cb c1 e1 03 ba ff 00 00 00 d3 e2 23 16 8b cb c1 e1 03 d3 ea e8 } //64 00 
		$a_03_1 = {8a 03 33 d2 8a d0 25 ff 00 00 00 d1 e8 2b d0 33 c0 8a 44 13 01 a3 90 01 02 40 00 33 c0 8a 03 33 d2 8a 13 d1 ea 2b c2 0f b6 04 03 90 00 } //32 00 
		$a_01_2 = {6d 7a 6f 2e 68 6f 70 74 6f 2e 6f 72 67 3a } //1e 00  mzo.hopto.org:
		$a_01_3 = {89 45 e8 89 55 ec 83 7d ec 00 75 08 83 7d e8 00 77 bc eb 02 7f b8 84 db 74 0b 57 e8 } //14 00 
		$a_00_4 = {2d 63 6f 72 65 } //14 00  -core
		$a_01_5 = {43 61 72 76 69 65 72 } //0a 00  Carvier
		$a_01_6 = {73 79 74 65 6d 33 32 2e 64 6c 6c } //0a 00  sytem32.dll
		$a_01_7 = {7b 31 32 46 34 38 38 38 31 2d 46 46 36 44 2d 34 33 41 31 2d 42 38 30 42 2d 39 32 36 35 43 32 35 43 43 39 46 36 7d 5c } //0a 00  {12F48881-FF6D-43A1-B80B-9265C25CC9F6}\
		$a_01_8 = {0a 00 00 00 47 45 54 53 45 52 56 45 52 7c } //0a 00 
		$a_01_9 = {05 00 00 00 48 41 52 4d 7c } //00 00 
		$a_00_10 = {80 10 00 00 93 7a 29 7b 42 a4 07 fe c9 c1 d9 a9 00 10 00 80 5d 04 00 00 5e ca 02 80 5c 20 00 00 5f ca 02 80 00 00 01 00 06 00 0a 00 84 21 46 61 72 66 6c 69 2e 5a 00 00 02 40 05 82 42 00 04 00 67 16 00 00 e0 a0 } //51 ed 
	condition:
		any of ($a_*)
 
}