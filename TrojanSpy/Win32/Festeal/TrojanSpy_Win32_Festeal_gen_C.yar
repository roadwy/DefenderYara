
rule TrojanSpy_Win32_Festeal_gen_C{
	meta:
		description = "TrojanSpy:Win32/Festeal.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {6f 73 3d 25 64 26 76 65 72 3d 25 73 26 69 64 78 3d 25 73 26 75 73 65 72 3d 25 73 } //os=%d&ver=%s&idx=%s&user=%s  2
		$a_80_1 = {25 73 26 69 6f 63 74 6c 3d 25 64 26 64 61 74 61 3d 25 73 } //%s&ioctl=%d&data=%s  2
		$a_00_2 = {44 37 45 42 36 30 38 35 2d 45 37 30 41 2d 34 66 35 61 2d 39 39 32 31 2d 45 36 42 44 32 34 34 41 38 43 31 37 00 } //4
		$a_03_3 = {c7 46 20 32 00 00 00 0f 84 ?? ?? 00 00 83 7e 14 24 0f 86 ?? ?? 00 00 6a 24 68 ?? ?? ?? ?? 50 e8 } //8
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_00_2  & 1)*4+(#a_03_3  & 1)*8) >=10
 
}