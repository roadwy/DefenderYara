
rule Backdoor_Win32_Faitypelf_B{
	meta:
		description = "Backdoor:Win32/Faitypelf.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5b 6d 73 6e 62 6f 74 5d 20 2d 20 74 68 65 20 70 72 6f 67 72 61 6d 28 25 73 29 20 68 61 73 20 62 65 65 6e 20 72 75 6e 6e 65 64 2c 50 49 44 3d 30 78 25 78 21 0d 0a 00 } //1
		$a_00_1 = {2d 75 73 65 72 20 00 00 2d 77 61 69 74 20 00 00 2d 63 68 65 63 6b 20 00 2d 68 69 64 65 20 00 00 66 61 69 6c 65 64 20 74 6f 20 66 69 6e 64 20 70 61 73 73 77 6f 72 64 20 28 25 53 2f 25 53 29 20 69 6e 20 6d 65 6d 6f 72 79 21 00 } //1
		$a_00_2 = {75 6e 61 62 6c 65 20 74 6f 20 6c 69 73 74 65 6e 20 73 6f 63 6b 65 74 00 } //1
		$a_01_3 = {8b 74 a9 04 80 3e 2d 0f 84 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}