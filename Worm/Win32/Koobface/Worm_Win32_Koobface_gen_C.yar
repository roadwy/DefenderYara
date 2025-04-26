
rule Worm_Win32_Koobface_gen_C{
	meta:
		description = "Worm:Win32/Koobface.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 0c 46 81 fe 10 27 00 00 7c c4 5e c9 c3 } //2
		$a_01_1 = {8d 4d fc 6a 00 51 ff d0 85 c0 74 0a f6 45 fc 07 74 04 b0 01 } //1
		$a_01_2 = {80 7c 30 ff 0d 59 75 0b 56 e8 } //1
		$a_01_3 = {80 38 7c 75 03 89 45 1c } //1
		$a_01_4 = {54 49 25 73 5f 4d 00 00 54 4c 45 00 4c 25 73 5f } //1
		$a_01_5 = {63 6b 3d 25 64 26 63 5f 66 62 3d 25 64 } //1 ck=%d&c_fb=%d
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}