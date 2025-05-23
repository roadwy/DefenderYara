
rule Worm_Win32_Autorun_gen_AX{
	meta:
		description = "Worm:Win32/Autorun.gen!AX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_00_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_00_2 = {73 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d } //1 shell\Open\command=
		$a_02_3 = {43 61 62 69 6e 65 74 57 43 6c 61 73 73 90 05 10 01 00 4d 79 20 43 6f 6d 70 75 74 65 72 } //2
		$a_01_4 = {83 f8 04 74 16 83 f8 06 74 11 83 f8 02 74 0c 83 f8 05 74 07 83 f8 00 74 02 } //5
		$a_03_5 = {83 f8 02 74 1a 83 f8 04 74 15 83 f8 06 74 10 83 3d ?? ?? ?? ?? 00 74 05 83 f8 03 74 02 90 09 40 00 [0-10] c6 05 ?? ?? ?? ?? 62 fe 05 ?? ?? ?? ?? 80 3d ?? ?? ?? ?? 7b } //8
		$a_03_6 = {89 c3 83 c3 12 80 3b 7a 0f 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 } //6
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*2+(#a_01_4  & 1)*5+(#a_03_5  & 1)*8+(#a_03_6  & 1)*6) >=6
 
}