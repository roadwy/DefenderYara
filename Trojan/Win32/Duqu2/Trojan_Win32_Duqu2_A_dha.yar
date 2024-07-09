
rule Trojan_Win32_Duqu2_A_dha{
	meta:
		description = "Trojan:Win32/Duqu2.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_03_0 = {b8 00 00 00 00 4c 8b d1 0f 05 c3 ?? b8 00 00 00 00 8d 54 24 04 cd 2e c2 00 00 } //10
		$a_00_1 = {53 65 74 43 6c 61 73 73 4c 6f 6e 67 41 } //10 SetClassLongA
		$a_00_2 = {44 65 73 74 72 6f 79 57 69 6e 64 6f 77 } //10 DestroyWindow
		$a_00_3 = {52 65 67 69 73 74 65 72 43 6c 61 73 73 41 } //10 RegisterClassA
		$a_01_4 = {b9 82 00 00 c0 0f 32 } //1
		$a_01_5 = {b9 76 01 00 00 0f 32 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=41
 
}