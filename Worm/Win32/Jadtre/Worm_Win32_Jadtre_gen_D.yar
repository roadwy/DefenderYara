
rule Worm_Win32_Jadtre_gen_D{
	meta:
		description = "Worm:Win32/Jadtre.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 45 a8 43 3a 5c 63 c7 45 ac 6d 74 2e 65 c7 45 b0 78 65 00 00 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 } //2
		$a_01_1 = {61 74 20 5c 5c 25 73 20 25 64 3a 25 64 20 43 3a 5c 25 73 2e 65 78 65 } //1 at \\%s %d:%d C:\%s.exe
		$a_01_2 = {25 73 26 66 6c 61 67 3d 25 73 26 61 6c 65 78 61 3d 30 26 4c 69 73 74 3d 25 73 } //1 %s&flag=%s&alexa=0&List=%s
		$a_03_3 = {62 72 6f 77 73 65 72 [0-04] 5c 5c 25 73 5c 70 69 70 65 25 73 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}