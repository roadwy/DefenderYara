
rule Worm_Win32_Autorun_gen_BL{
	meta:
		description = "Worm:Win32/Autorun.gen!BL,SIGNATURE_TYPE_PEHSTR_EXT,23 00 20 00 08 00 00 "
		
	strings :
		$a_00_0 = {6d 69 63 72 6f 73 6f 66 74 20 76 69 73 75 61 6c 20 63 2b 2b 20 72 75 6e 74 69 6d 65 20 6c 69 62 72 61 72 79 } //15 microsoft visual c++ runtime library
		$a_01_1 = {b1 68 a9 00 01 00 00 74 02 b1 69 a9 00 02 00 00 74 02 b1 6a a9 00 04 00 00 74 02 b1 6b a9 00 08 00 00 74 02 b1 6c a9 00 10 00 00 b0 6d 75 02 8a c1 59 c3 } //15
		$a_01_2 = {0f be d3 89 54 24 14 e8 fb cd ff ff 8a d8 88 5c 24 13 3a 5c 24 12 74 06 88 5c 24 12 eb 0b 83 7c 24 1c 00 0f 85 e9 00 00 00 8b 44 24 14 50 8d 8c 24 34 01 00 00 68 } //4
		$a_00_3 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 66 75 6e 2e 65 78 65 } //1 shell\explore\Command=fun.exe
		$a_00_4 = {25 63 3a 5c 6b 69 6c 6c 76 62 73 2e 76 62 73 } //1 %c:\killvbs.vbs
		$a_00_5 = {25 63 3a 5c 6e 74 64 65 31 65 63 74 2e 63 6f 6d } //1 %c:\ntde1ect.com
		$a_00_6 = {25 63 3a 5c 2c 2e 65 78 65 } //1 %c:\,.exe
		$a_00_7 = {25 63 3a 5c 62 69 74 40 75 6f 6d 2e 76 62 73 } //1 %c:\bit@uom.vbs
	condition:
		((#a_00_0  & 1)*15+(#a_01_1  & 1)*15+(#a_01_2  & 1)*4+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=32
 
}