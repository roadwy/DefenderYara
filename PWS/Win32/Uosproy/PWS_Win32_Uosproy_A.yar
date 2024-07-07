
rule PWS_Win32_Uosproy_A{
	meta:
		description = "PWS:Win32/Uosproy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 06 e9 89 6e 01 83 e9 05 8d 54 24 08 52 c6 04 1f e9 89 4c 1f 01 } //1
		$a_03_1 = {33 d0 81 f2 90 01 04 89 90 90 90 01 04 40 8d 94 01 90 01 04 81 fa 90 01 04 7e da 90 00 } //1
		$a_01_2 = {25 73 3f 69 64 3d 25 73 26 6d 6d 3d 25 73 26 6c 65 76 65 6c 3d 25 64 26 79 79 69 64 3d 25 64 26 62 69 61 6f 71 3d 25 73 26 76 65 72 3d 25 73 26 79 79 76 65 72 3d 25 73 } //1 %s?id=%s&mm=%s&level=%d&yyid=%d&biaoq=%s&ver=%s&yyver=%s
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}