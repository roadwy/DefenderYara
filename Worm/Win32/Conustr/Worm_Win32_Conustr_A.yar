
rule Worm_Win32_Conustr_A{
	meta:
		description = "Worm:Win32/Conustr.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 70 00 78 00 78 00 78 00 78 00 } //1 ppxxxx
		$a_00_1 = {54 00 39 00 5b 00 51 00 44 00 42 00 58 00 42 00 4b 00 44 00 51 00 5b 00 43 00 62 00 65 00 6b 00 78 00 2d 00 64 00 77 00 64 00 } //1 T9[QDBXBKDQ[Cbekx-dwd
		$a_00_2 = {56 f7 d1 2b f9 6a 02 8b d1 8b f7 8b f8 c1 e9 02 f3 a5 8b ca 83 e1 03 } //1
		$a_03_3 = {80 3e 63 74 4a 80 fb 02 75 1c 8d 54 24 10 c6 06 01 52 e8 ?? 00 00 00 83 c4 04 f7 d8 1a c0 24 64 fe c8 88 06 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}