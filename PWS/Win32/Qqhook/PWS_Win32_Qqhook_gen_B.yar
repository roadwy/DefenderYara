
rule PWS_Win32_Qqhook_gen_B{
	meta:
		description = "PWS:Win32/Qqhook.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 08 00 "
		
	strings :
		$a_02_0 = {75 1a 6a 00 a1 90 01 03 00 50 b8 90 01 03 00 50 6a 90 01 01 e8 90 01 04 a3 90 01 03 00 83 3d 90 01 03 00 00 75 1a 6a 00 a1 90 01 03 00 50 b8 90 01 03 00 50 6a 90 01 01 e8 90 01 04 a3 90 01 03 00 c3 90 09 07 00 83 3d 90 01 03 00 00 90 00 } //05 00 
		$a_02_1 = {53 56 57 8b fa 8b f0 8b c6 e8 90 01 04 8b d8 eb 01 4b 85 db 7e 15 80 7c 1e ff 5c 74 0e 80 7c 1e ff 3a 74 07 80 7c 1e ff 2f 75 e6 57 8b c6 e8 90 01 04 8b c8 2b cb 8d 53 01 8b c6 e8 90 01 04 5f 5e 5b c3 90 00 } //01 00 
		$a_00_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_00_3 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //02 00  Content-Type: application/x-www-form-urlencoded
		$a_00_4 = {48 6f 6f 6b 4f 66 66 00 } //02 00  潈歯晏f
		$a_00_5 = {51 51 50 57 44 } //02 00  QQPWD
		$a_00_6 = {00 4e 75 6d 62 65 72 3d 00 } //02 00 
		$a_00_7 = {00 26 50 61 73 73 57 6f 72 64 3d 00 } //02 00  ☀慐獳潗摲=
		$a_00_8 = {00 26 49 50 3d 00 } //02 00  ☀偉=
		$a_00_9 = {51 51 48 6f 6f 6b } //02 00  QQHook
		$a_00_10 = {48 6f 6f 6b 43 6c 61 73 73 } //00 00  HookClass
	condition:
		any of ($a_*)
 
}