
rule Trojan_Win32_Ropest_J{
	meta:
		description = "Trojan:Win32/Ropest.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 53 54 45 52 4f 50 45 } //1 ASTEROPE
		$a_00_1 = {56 42 6f 78 4d 6f 75 73 65 2e 73 79 73 00 } //1
		$a_01_2 = {77 69 6e 65 5f 67 65 74 5f 75 6e 69 78 5f 66 69 6c 65 5f 6e 61 6d 65 00 } //1 楷敮束瑥畟楮彸楦敬湟浡e
		$a_00_3 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8 } //1
		$a_00_4 = {3d 40 1a cd 00 0f 84 3f 01 00 00 3d 08 c5 bb 6c 0f 84 34 01 00 00 3d 82 16 4e 77 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}